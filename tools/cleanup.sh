#!/bin/bash

# CONFIGURATION & GLOBAL VARIABLES

# Associative array for exclusions
declare -A EXCLUSION_MAP
ERROR_COUNT=0

# Environment Variables expected from Cloud Build
PROJECT_ID="${PROJECT_ID:-hpc-toolkit-dev}"
DRY_RUN="${DRY_RUN:-true}"
EXCLUSION_FILE="${EXCLUSION_FILE:-gs://hpc-ctk1357/cleanup/exclusions.txt}"
CUTOFF_TIME="${CUTOFF_TIME:-$(date -d '2 hours ago' -u +%Y-%m-%dT%H:%M:%S%z)}"
CUTOFF_TIME_IMAGES="${CUTOFF_TIME_IMAGES:-$(date -d "60 days ago" -u +%Y-%m-%dT%H:%M:%S%z)}"

# To store IPs of protected instances, to find matching Address resources
declare -A PROTECTED_IPS

# HELPER FUNCTIONS

log() {
    local level="$1"
    local message="$2"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [$level] $message"
}

check_dependencies() {
    local dependencies=("gcloud" "awk" "grep" "sort" "date" "sed" "basename")
    for cmd in "${dependencies[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log "ERROR" "Missing required dependency: $cmd"
            exit 1 # Dependencies are critical, we must exit immediately here.
        fi
    done
}

load_exclusions() {
    log "INFO" "Loading exclusions from $EXCLUSION_FILE..."

    local line_count=0
    # Helper function to process each line from the exclusion source
    process_line() {
        local line="$1"
        local trimmed_line
        trimmed_line=$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        if [[ -n "$trimmed_line" ]] && [[ "$trimmed_line" != \#* ]]; then
            if [[ -z "${EXCLUSION_MAP[${trimmed_line}]:-}" ]]; then
                 EXCLUSION_MAP["${trimmed_line}"]=1
                 ((line_count++))
            fi
        fi
    }

    log "INFO" "Exclusion file is a GCS path. Streaming content..."
    # Preliminary check to see if the GCS object exists and is accessible
    if ! gcloud storage ls "$EXCLUSION_FILE" > /dev/null 2>&1; then
        log "ERROR" "Cannot access GCS exclusion file: $EXCLUSION_FILE. Please check the path and permissions."
        exit 1
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        process_line "$line"
    done < <(gcloud storage cat "$EXCLUSION_FILE")

    if [[ ${#EXCLUSION_MAP[@]} -eq 0 ]]; then
        log "ERROR" "No valid exclusion entries loaded from $EXCLUSION_FILE. Exiting to prevent accidental deletion."
        exit 1
    else
        log "INFO" "Loaded ${#EXCLUSION_MAP[@]} unique exclusion entries."
    fi
}


# Returns 0 if EXCLUDED (do NOT delete)
# Returns 1 if NOT excluded (OK to delete)
is_excluded() {
    local resource_name="$1"
    local labels_str="${2:-}" # Expected format: key1=value1;key2=value2

    if [[ -n "${EXCLUSION_MAP[${resource_name}]:-}" ]]; then
        log "SKIP" "$resource_name (In Exclusion Map)"
        return 0 # Excluded
    fi

    if [[ -n "$labels_str" ]]; then
        IFS=';' read -ra LABEL_PAIRS <<< "$labels_str"
        for PAIR in "${LABEL_PAIRS[@]}"; do
            local KEY VAL
            KEY="${PAIR%%=*}"
            VAL="${PAIR#*=}"
            if [[ "$KEY" == "do-not-delete" ]]; then
                if [[ "$VAL" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
                    local exp_seconds
                    if ! exp_seconds=$(date -d "$VAL + 1 day" -u +%s 2>/dev/null); then
                         log "WARNING" "$resource_name (Label: do-not-delete invalid date value: $VAL)"
                         return 1 # Not excluded
                    else
                        local current_seconds
                        current_seconds=$(date -u +%s)
                        if [[ "$exp_seconds" -gt "$current_seconds" ]]; then
                            log "SKIP" "$resource_name (Label: do-not-delete=$VAL, valid)"
                            return 0 # Excluded
                        else
                            log "INFO" "$resource_name (Label: do-not-delete=$VAL expired)"
                            return 1 # Not excluded
                        fi
                    fi
                else
                    log "WARNING" "$resource_name (Label: do-not-delete invalid date format: $VAL, expected YYYY-MM-DD)"
                    return 1 # Not excluded
                fi
                break
            fi
        done
    fi
    return 1 # Not excluded
}

execute_delete() {
    local resource_type="$1"
    local resource_name="$2"
    local cmd_str="$3"
    local extra_info="${4:-}"

    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY-RUN" "Would delete $resource_type: $resource_name $extra_info"
    else
        log "EXECUTE" "Deleting $resource_type: $resource_name $extra_info"
        if eval "$cmd_str"; then
            log "SUCCESS" "Deleted $resource_name"
        else
            log "ERROR" "Failed to delete $resource_name"
            ((ERROR_COUNT++)) || true
        fi
    fi
}

populate_protected_resources() {
    log "INFO" "Identifying protected instances and their associated resources..."
    local instances_data
    if ! instances_data=$(gcloud compute instances list \
        --project="$PROJECT_ID" \
        --filter="labels.do-not-delete:*" \
        --format="value(name,zone.basename(),labels.map(),disks[].source.list(separator=';'),networkInterfaces[].network.list(separator=';'),networkInterfaces[].subnetwork.list(separator=';'),networkInterfaces[].networkIP.list(separator=';'),networkInterfaces[].accessConfigs[].natIP.list(separator=';'))"); then
        log "ERROR" "Failed to list instances with do-not-delete label."
        ((ERROR_COUNT++)) || true
        return
    fi

    if [[ -z "$instances_data" ]]; then
        log "INFO" "No instances found with do-not-delete label."
        return
    fi

    while IFS=$'\t' read -r inst_name zone labels_str disks_list nets_list subs_list ips_list nat_ips_list; do
        if is_excluded "$inst_name" "$labels_str"; then # Returns 0 if excluded
            log "INFO" "Instance ${inst_name} in ${zone} is PROTECTED. Adding associated resources to exclusions."
            EXCLUSION_MAP["${inst_name}"]=1

            # Protect Attached Disks
            IFS=';' read -ra disk_urls <<< "$disks_list"
            for disk_url in "${disk_urls[@]}"; do
                [[ -z "$disk_url" ]] && continue
                local disk_name
                disk_name=$(basename "${disk_url}")
                if [[ -n "${disk_name}" && -z "${EXCLUSION_MAP[${disk_name}]:-}" ]]; then
                     log "INFO" "  > Excluding Disk: ${disk_name}"
                     EXCLUSION_MAP["${disk_name}"]=1
                fi
            done

            # Protect Network
            IFS=';' read -ra net_urls <<< "$nets_list"
            for net_url in "${net_urls[@]}"; do
                 [[ -z "$net_url" ]] && continue
                 local net_name
                 net_name=$(basename "${net_url}")
                 if [[ -n "${net_name}" && -z "${EXCLUSION_MAP[${net_name}]:-}" ]]; then
                    log "INFO" "  > Excluding Network: ${net_name}"
                    EXCLUSION_MAP["${net_name}"]=1
                 fi
            done

            # Protect Subnetwork
            IFS=';' read -ra sub_urls <<< "$subs_list"
            for sub_url in "${sub_urls[@]}"; do
                 [[ -z "$sub_url" ]] && continue
                 local sub_name
                 sub_name=$(basename "${sub_url}")
                 if [[ -n "${sub_name}" && -z "${EXCLUSION_MAP[${sub_name}]:-}" ]]; then
                         log "INFO" "  > Excluding Subnetwork: ${sub_name}"
                         EXCLUSION_MAP["${sub_name}"]=1
                 fi
            done

            # Protect Network IPs
            IFS=';' read -ra network_ips <<< "$ips_list"
            for ip in "${network_ips[@]}"; do
                [[ -n "$ip" ]] && PROTECTED_IPS["${ip}"]=1
            done

            # Protect External (NAT) IPs
            IFS=';' read -ra nat_ips <<< "$nat_ips_list"
            for ip in "${nat_ips[@]}"; do
                 [[ -n "$ip" ]] && PROTECTED_IPS["${ip}"]=1
            done
        fi
    done <<< "$instances_data"

    # Find Address resource names for the PROTECTED_IPS
    if ((${#PROTECTED_IPS[@]} > 0)); then
        log "INFO" "Finding Address resource names for protected IPs..."
        local addresses_data
        if ! addresses_data=$(gcloud compute addresses list --project="$PROJECT_ID" --format="value(name,address)"); then
            log "WARNING" "Failed to list addresses to protect by IP."
        else
            while IFS=$'\t' read -r addr_name addr_ip; do
                 if [[ -n "${addr_ip}" && -n "${PROTECTED_IPS[${addr_ip}]:-}" ]]; then
                    if [[ -n "${addr_name}" && -z "${EXCLUSION_MAP[${addr_name}]:-}" ]]; then
                        log "INFO" "  > Excluding Address: ${addr_name} (${addr_ip})"
                        EXCLUSION_MAP["${addr_name}"]=1
                    fi
                 fi
            done <<< "$addresses_data"
        fi
    fi
}

log_exclusion_map() {
    log "INFO" "--- Current Exclusion Map Contents ---"
    if [ ${#EXCLUSION_MAP[@]} -eq 0 ]; then
        log "INFO" "Exclusion map is empty."
        return
    fi
    for key in "${!EXCLUSION_MAP[@]}"; do
        log "INFO" "EXCLUDED: $key"
    done
    log "INFO" "--- End of Exclusion Map ---"
}

# STANDARD PROCESSOR

process_resources() {
    local label="$1"
    local list_command="$2"
    local delete_command_base="$3"
    local scope_type="$4"

    log "INFO" "--- Processing: $label ---"

    local resources
    if ! resources=$(eval "$list_command"); then
        log "ERROR" "Failed to list $label"
        ((ERROR_COUNT++)) || true
        return 0
    fi

    if [[ -z "$resources" ]]; then
        log "INFO" "No $label found matching criteria."
        return 0
    fi

    local count=0
    while IFS=$'\t' read -r name scope labels_str; do
        [[ -z "$name" ]] && continue

        if ! is_excluded "$name" "${labels_str:-}"; then
            local final_cmd="$delete_command_base \"$name\" --quiet"
            if [[ "$scope_type" != "none" && -n "$scope" ]]; then
                final_cmd="$final_cmd --$scope_type=\"$scope\""
            fi

            execute_delete "$label" "$name" "$final_cmd" "${scope:-(Global)}"
            ((count++)) || true
        fi
    done <<< "$resources"
}

# SPECIFIC HANDLERS

process_instance_templates() {
    log "INFO" "--- Processing: Instance Templates ---"
    local templates
    if ! templates=$(gcloud compute instance-templates list \
        --project="$PROJECT_ID" \
        --filter="creationTimestamp < '$CUTOFF_TIME'" \
        --format="value(name, labels.map())" | sort); then
        log "ERROR" "Failed to list instance templates."
        ((ERROR_COUNT++)) || true
        return 0
    fi
    if [[ -z "$templates" ]]; then log "INFO" "No instance templates found matching criteria."; return 0; fi

    local count=0
    while IFS=$'\t' read -r name labels_str; do
        if [[ -z "$name" ]]; then continue; fi
        if ! is_excluded "$name" "${labels_str:-}"; then
            execute_delete "Instance Template" "$name" \
                "gcloud compute instance-templates delete \"$name\" --project=\"$PROJECT_ID\" --quiet" \
                "(Global)"
            ((count++)) || true
        fi
    done <<< "$templates"
}

process_addresses() {
    log "INFO" "--- Processing: Compute Addresses ---"
    # Regional Addresses
     local regional_addresses
    if ! regional_addresses=$(gcloud compute addresses list --project="$PROJECT_ID" \
        --filter="creationTimestamp < '$CUTOFF_TIME' AND region:*" \
        --format="value(name,region.basename(),labels.map(),status)" | sort); then
        log "ERROR" "Failed to list Regional Addresses."
        ((ERROR_COUNT++)) || true
    else
        while IFS=$'\t' read -r name region labels_str status; do
            [[ -z "$name" ]] && continue
            if ! is_excluded "$name" "${labels_str:-}"; then
                 if [[ "$status" == "IN_USE" ]]; then
                    log "WARNING" "Skipping IN_USE Regional Address $name ($region) NOT explicitly excluded."
                    continue
                 fi
                execute_delete "Regional Address" "$name" \
                    "gcloud compute addresses delete \"$name\" --project=\"$PROJECT_ID\" --region=\"$region\" --quiet" \
                    "($region)"
            fi
        done <<< "$regional_addresses"
    fi

    # Global Addresses
    local global_addresses
    if ! global_addresses=$(gcloud compute addresses list --project="$PROJECT_ID" \
        --filter="creationTimestamp < '$CUTOFF_TIME' AND NOT region:*" \
         --format="value(name, labels.map(), status)" | sort); then
         log "ERROR" "Failed to list Global Addresses."
         ((ERROR_COUNT++)) || true
    else
        while IFS=$'\t' read -r name labels_str status; do
            [[ -z "$name" ]] && continue
            if ! is_excluded "$name" "${labels_str:-}"; then
                 if [[ "$status" == "IN_USE" ]]; then
                    log "WARNING" "Skipping IN_USE Global Address $name NOT explicitly excluded."
                    continue
                 fi
                execute_delete "Global Address" "$name" \
                    "gcloud compute addresses delete \"$name\" --project=\"$PROJECT_ID\" --global --quiet" \
                    "(Global)"
            fi
        done <<< "$global_addresses"
    fi
}


process_vpc_peerings() {
    log "INFO" "--- Processing: VPC Peerings---"
    local networks_data
    if ! networks_data=$(gcloud compute networks list --project="$PROJECT_ID" --format="value(name)"); then
        log "ERROR" "Failed to list networks."
        ((ERROR_COUNT++)) || true
        return 0
    fi
    if [[ -z "$networks_data" ]]; then log "INFO" "No networks found in project."; return 0; fi

    local count=0
    while IFS=$'\t' read -r net_name; do
        if [[ -z "$net_name" ]]; then continue; fi

        if [[ -n "${EXCLUSION_MAP[${net_name}]:-}" ]]; then
            log "SKIP" "VPC Peerings for Network $net_name (Protected)"
            continue
        fi

        local peerings_data
        if ! peerings_data=$(gcloud compute networks peerings list --network="$net_name" --project="$PROJECT_ID" --format="value(name,network,state)"); then
            log "WARNING" "Failed to list peerings for network $net_name"
            continue
        fi

        if [[ -z "$peerings_data" ]]; then continue; fi

        while IFS=$'\t' read -r peering_name peer_network state; do
            if [[ -z "$peering_name" ]]; then continue; fi

            if ! is_excluded "$peering_name"; then
                if [[ "$peering_name" == "servicenetworking-googleapis-com" ]]; then
                    execute_delete "Service Peering" "$peering_name" \
                        "gcloud services vpc-peerings delete --service=servicenetworking.googleapis.com --network=\"$net_name\" --project=\"$PROJECT_ID\" --quiet" \
                        "(Network: $net_name)"
                    ((count++)) || true
                elif [[ "$peering_name" == filestore-peer-* ]]; then continue;
                elif [[ "$peer_network" == *"/global/networks/servicenetworking" ]]; then continue;
                else
                    execute_delete "VPC Peering" "$peering_name" \
                       "gcloud compute networks peerings delete \"$peering_name\" --network=\"$net_name\" --project=\"$PROJECT_ID\" --quiet" \
                       "(Network: $net_name, State: $state)"
                    ((count++)) || true
                fi
            fi
        done <<< "$peerings_data"
    done <<< "$networks_data"
    log "INFO" "Finished processing VPC Peerings. $count peerings actioned."
}

process_iam_deleted_members() {
    log "INFO" "--- Processing: IAM Role Bindings for Deleted SAs ---"
    local policy_data
    if ! policy_data=$(gcloud projects get-iam-policy "$PROJECT_ID" --format="value(bindings[].role,bindings[].members)"); then
        log "ERROR" "Failed to get IAM policy."
        ((ERROR_COUNT++)) || true
        return 0
    fi
    if [[ -z "$policy_data" ]]; then log "INFO" "No IAM bindings found."; return 0; fi

    local count=0
    while IFS=$'\t' read -r role members_str; do
        if [[ -z "$role" || -z "$members_str" ]]; then continue; fi

        IFS=';' read -ra members <<< "$members_str"
        for member in "${members[@]}"; do
            if [[ "$member" == deleted:serviceAccount:* ]]; then
                local cmd="gcloud projects remove-iam-policy-binding \"$PROJECT_ID\" --member=\"$member\" --role=\"$role\" --condition=None --quiet"

                if [[ "$DRY_RUN" == "true" ]]; then
                    log "DRY-RUN" "Would remove IAM binding: $member from role $role"
                else
                    log "EXECUTE" "Removing IAM binding: $member from role $role"
                    if ! eval "$cmd" >/dev/null; then
                        log "ERROR" "Failed to remove binding for $member in $role"
                        ((ERROR_COUNT++)) || true
                    fi
                fi
                ((count++)) || true
            fi
        done
    done <<< "$policy_data"
    log "INFO" "Finished processing IAM deleted members. $count bindings actioned."
}

process_vm_images() {
    log "INFO" "--- Processing: VM Images ---"
    local images
    if ! images=$(gcloud compute images list --project="$PROJECT_ID" --no-standard-images \
        --format="value(name,creationTimestamp,labels.map())"); then
        log "ERROR" "Failed to list VM images"
        ((ERROR_COUNT++)) || true
        return 0
    fi
    if [[ -z "$images" ]]; then log "INFO" "No custom VM images found."; return 0; fi
    local cutoff_seconds
    if ! cutoff_seconds=$(date -d "$CUTOFF_TIME_IMAGES" +%s); then
        log "ERROR" "Failed to calculate cutoff time for images"
        ((ERROR_COUNT++)) || true
        return 0
    fi
    local count=0
    while IFS=$'\t' read -r name timestamp labels_str; do
        [[ -z "$name" ]] && continue
        if ! is_excluded "$name" "${labels_str:-}"; then
            local ts_seconds
            if ! ts_seconds=$(date -d "$timestamp" +%s 2>/dev/null); then
                log "WARNING" "Could not parse timestamp '$timestamp' for image $name. Skipping."
                continue
            fi
            if [[ $ts_seconds -lt $cutoff_seconds ]]; then
                 execute_delete "VM Image" "$name" \
                    "gcloud compute images delete \"$name\" --project=\"$PROJECT_ID\" --quiet"
                 ((count++)) || true
            fi
        fi
    done <<< "$images"
}

process_docker_images() {
    log "INFO" "--- Processing: Docker Images for 'test-runner' (Artifact Registry) ---"
    local cutoff_date=$(date -u -d "14 days ago" '+%Y-%m-%dT%H:%M:%SZ')
    local cutoff_seconds
    if ! cutoff_seconds=$(date -u -d "$cutoff_date" +%s); then
        log "ERROR" "Failed to calculate cutoff_seconds."
        ((ERROR_COUNT++)) || true
        return 0
    fi
    local location="us-central1"
    local repo_name="hpc-toolkit-repo"
    local package_name="test-runner"
    local full_package_url="${location}-docker.pkg.dev/${PROJECT_ID}/${repo_name}/${package_name}"
    local images_output
    if ! images_output=$(gcloud artifacts docker images list "$full_package_url" --format="csv[no-heading](uri,updateTime)" --sort-by="updateTime" 2>/dev/null); then
        log "WARNING" "Failed to list images for $full_package_url (Repo might not exist or empty)"
        return 0
    fi
    if [[ -z "$images_output" ]]; then log "INFO" "  > No image versions found for $package_name."; return 0; fi
    local count=0
    while IFS=, read -r full_image_ref update_time; do
         if [[ -z "$full_image_ref" || -z "$update_time" || "$full_image_ref" != *"@sha256:"* ]]; then continue; fi
         local image_seconds
         if ! image_seconds=$(date -u -d "$update_time" +%s 2>/dev/null); then continue; fi
         if [[ $image_seconds -lt $cutoff_seconds ]]; then
             if ! is_excluded "$package_name" && ! is_excluded "$full_image_ref"; then
                 execute_delete "Docker Image Version" "$full_image_ref" \
                     "gcloud artifacts docker images delete \"$full_image_ref\" --project=\"$PROJECT_ID\" --delete-tags --quiet" \
                     "(Updated: $update_time)"
                 ((count++)) || true
             fi
         fi
    done <<< "$images_output"
}

process_firewalls() {
    log "INFO" "--- Processing: Firewall Rules ---"
    local fws
    if ! fws=$(gcloud compute firewall-rules list --project="$PROJECT_ID" \
        --filter="creationTimestamp < '$CUTOFF_TIME'" \
        --format="value(name,network,labels.map())" | sort); then
        log "ERROR" "Failed to list firewall rules"
        ((ERROR_COUNT++)) || true
        return 0
    fi
    if [[ -z "$fws" ]]; then log "INFO" "No Firewall Rules found matching criteria."; return 0; fi

    local count=0
    while IFS=$'\t' read -r name network_uri labels_str; do
        [[ -z "$name" ]] && continue
        local network_name
        network_name=$(basename "$network_uri")
        if [[ "$network_name" == "default" ]]; then continue; fi

        if [[ -n "${EXCLUSION_MAP[${network_name}]:-}" ]]; then
            log "SKIP" "Firewall Rule $name - Network $network_name is protected."
            continue
        fi

        if ! is_excluded "$name" "${labels_str:-}"; then
            execute_delete "Firewall Rule" "$name" \
                "gcloud compute firewall-rules delete \"$name\" --project=\"$PROJECT_ID\" --quiet"
            ((count++)) || true
        fi
    done <<< "$fws"
}

process_filestore() {
    log "INFO" "--- Processing: Filestore Instances ---"
    local fs_data
    # Get instance name, location, and labels using segment projections
    if ! fs_data=$(gcloud filestore instances list --project="$PROJECT_ID" --filter="createTime < '$CUTOFF_TIME'" \
        --format="value(name.segment(5), name.segment(3), labels.map())"); then
        log "ERROR" "Failed to list Filestore instances."
        ((ERROR_COUNT++)) || true
        return 0
    fi
    if [[ -z "$fs_data" ]]; then log "INFO" "No Filestore instances found matching criteria."; return 0; fi

    local count=0
    while IFS=$'\t' read -r name location labels_str; do
        # Trim potential whitespace
        name=$(echo "$name" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        location=$(echo "$location" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

        if [[ -z "$name" || "$name" == "None" || -z "$location" || "$location" == "None" ]]; then
            log "WARNING" "Could not extract valid name or location for a Filestore instance from line: $name  $location    $labels_str"
            continue
        fi

        if ! is_excluded "$name" "${labels_str:-}"; then
            log "INFO" "Processing Filestore instance: $name in $location"

            if [[ "$DRY_RUN" == "true" ]]; then
                log "DRY-RUN" "Would disable deletion protection on Filestore: $name ($location)"
                log "DRY-RUN" "Would delete Filestore: $name ($location)"
                ((count++)) || true
            else
                log "EXECUTE" "Attempting to disable deletion protection on Filestore: $name ($location)"
                local disable_cmd="gcloud filestore instances update \"$name\" --location=\"$location\" --project=\"$PROJECT_ID\" --no-deletion-protection --quiet"
                if ! eval "$disable_cmd"; then
                    log "WARNING" "Failed to disable deletion protection for $name. This may be OK if it was already disabled or the instance is not in a state to be updated. Continuing with delete attempt."
                else
                    log "INFO" "Deletion protection update command executed successfully for $name"
                fi

                log "EXECUTE" "Deleting Filestore: $name ($location)"
                local delete_cmd="gcloud filestore instances delete \"$name\" --project=\"$PROJECT_ID\" --location=\"$location\" --quiet --force"
                if eval "$delete_cmd"; then
                    log "SUCCESS" "Deleted Filestore $name"
                    ((count++)) || true
                else
                    log "ERROR" "Failed to delete Filestore $name"
                    ((ERROR_COUNT++)) || true
                fi
            fi
        fi
    done <<< "$fs_data"
}

process_subnetworks() {
    log "INFO" "--- Processing: Subnetworks ---"
    local subnets
    if ! subnets=$(gcloud compute networks subnets list --project="$PROJECT_ID" --filter="creationTimestamp < '$CUTOFF_TIME'" --format="value(name,region.basename(),network)"); then
        log "ERROR" "Failed to list subnets"
        ((ERROR_COUNT++)) || true
        return 0
    fi

    local count=0
    while IFS=$'\t' read -r name region network_uri; do
        [[ -z "$name" ]] && continue
        local network_name
        network_name=$(basename "$network_uri")
        if [[ "$network_name" == "default" ]]; then continue; fi

        if [[ -n "${EXCLUSION_MAP[${network_name}]:-}" ]]; then
            log "SKIP" "Subnetwork $name - Network $network_name is protected."
            continue
        fi
        if [[ -n "${EXCLUSION_MAP[${name}]:-}" ]]; then
             log "SKIP" "Subnetwork $name - Explicitly protected."
             continue
        fi

        if ! is_excluded "$name"; then
             # Dependent address cleanup can be added here if needed
            execute_delete "Subnetwork" "$name" "gcloud compute networks subnets delete \"$name\" --project=\"$PROJECT_ID\" --region=\"$region\" --quiet"
            ((count++)) || true
        fi
    done <<< "$subnets"
}

process_networks() {
    log "INFO" "--- Processing: VPC Networks ---"
     local networks
    if ! networks=$(gcloud compute networks list --project="$PROJECT_ID" --filter="creationTimestamp < '$CUTOFF_TIME'" --format="value(name,selfLink)"); then
        log "ERROR" "Failed to list networks"
        ((ERROR_COUNT++)) || true
        return 0
    fi

    local count=0
    while IFS=$'\t' read -r name self_link; do
        [[ -z "$name" ]] && continue
        if [[ "$name" == "default" ]]; then continue; fi
        if ! is_excluded "$name"; then
            local routes
            routes=$(gcloud compute routes list --project="$PROJECT_ID" --filter="network=\"$self_link\"" --format="value(name)" 2>/dev/null || true)
            for r in $routes; do if ! is_excluded "$r"; then execute_delete "Dep. Route" "$r" "gcloud compute routes delete \"$r\" --project=\"$PROJECT_ID\" --quiet"; fi; done

            local fws
            fws=$(gcloud compute firewall-rules list --project="$PROJECT_ID" --filter="network=\"$self_link\"" --format="value(name)" 2>/dev/null || true)
            for fw in $fws; do if ! is_excluded "$fw"; then execute_delete "Dep. FW" "$fw" "gcloud compute firewall-rules delete \"$fw\" --project=\"$PROJECT_ID\" --quiet"; fi; done

            execute_delete "Network" "$name" "gcloud compute networks delete \"$name\" --project=\"$PROJECT_ID\" --quiet"
            ((count++)) || true
        fi
    done <<< "$networks"
}

process_routers() {
    log "INFO" "--- Processing: Cloud Routers ---"
    local routers
    if ! routers=$(gcloud compute routers list --project="$PROJECT_ID" \
        --filter="creationTimestamp < '$CUTOFF_TIME'" \
        --format="value(name,region.basename(),network,labels.map())" | sort); then
        log "ERROR" "Failed to list Cloud Routers"
        ((ERROR_COUNT++)) || true
        return 0
    fi
    if [[ -z "$routers" ]]; then log "INFO" "No Cloud Routers found matching criteria."; return 0; fi

    local count=0
    while IFS=$'\t' read -r name region network_uri labels_str; do
        [[ -z "$name" ]] && continue

        local network_name
        network_name=$(basename "$network_uri")
        if [[ -n "${EXCLUSION_MAP[${network_name}]:-}" ]]; then
            log "SKIP" "Cloud Router $name - Network $network_name is protected."
            continue
        fi

        if ! is_excluded "$name" "${labels_str:-}"; then
            execute_delete "Cloud Router" "$name" \
                "gcloud compute routers delete \"$name\" --project=\"$PROJECT_ID\" --region=\"$region\" --quiet" \
                "($region)"
            ((count++)) || true
        fi
    done <<< "$routers"
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

main() {
    log "INFO" "STARTING RESOURCE CLEANUP: $PROJECT_ID"
    log "INFO" "Time Cutoff (General): $CUTOFF_TIME"
    log "INFO" "Time Cutoff (Images): $CUTOFF_TIME_IMAGES"
    log "INFO" "DRY_RUN: $DRY_RUN"
    log "INFO" "Exclusion File: $EXCLUSION_FILE"

    check_dependencies
    load_exclusions
    populate_protected_resources
    log_exclusion_map # Log the map contents

    # --- Phase 1: High Level Resources ---
    process_resources "GKE Cluster" \
        "gcloud container clusters list --project=\"$PROJECT_ID\" --filter=\"createTime < '$CUTOFF_TIME'\" --format=\"value(name,location,resourceLabels.map())\" | sort" \
        "gcloud container clusters delete --project=\"$PROJECT_ID\"" "location"
    process_resources "Instance Template" \
        "gcloud compute instance-templates list --project=\"$PROJECT_ID\" --filter=\"creationTimestamp < '$CUTOFF_TIME'\" --format=\"value(name, 'Global', labels.map())\" | sort" \
        "gcloud compute instance-templates delete --project=\"$PROJECT_ID\"" 
    process_resources "Compute Instance" \
        "gcloud compute instances list --project=\"$PROJECT_ID\" --filter=\"creationTimestamp < '$CUTOFF_TIME'\" --format=\"value(name,zone.basename(),labels.map())\" | sort" \
        "gcloud compute instances delete --project=\"$PROJECT_ID\" --delete-disks=all" "zone"
    process_filestore

    # --- Phase 2: Images & Artifacts ---
    process_vm_images
    process_docker_images

    # --- Phase 3: Network Infrastructure ---
    process_routers
    # process_firewalls # Called in process_networks for dependencies
    process_addresses
    process_resources "Zonal Disk" \
        "gcloud compute disks list --project=\"$PROJECT_ID\" --filter=\"creationTimestamp < '$CUTOFF_TIME' AND zone:*\" --format=\"value(name,zone.basename(),labels.map())\" | sort" \
        "gcloud compute disks delete --project=\"$PROJECT_ID\"" "zone"

    # # --- Phase 4: Networking Hierarchies ---
    process_subnetworks
    process_networks # This now handles dependent firewalls and routes

    # # --- Phase 5: IAM Cleanup ---
    process_iam_deleted_members

    log "INFO" "CLEANUP RUN FINISHED"

    if [[ $ERROR_COUNT -gt 0 ]]; then
        log "WARNING" "Finished with $ERROR_COUNT errors during execution."
        exit 1
    else
        log "SUCCESS" "Finished with 0 errors."
        exit 0
    fi
}

main
