#!/bin/bash

# ==============================================================================
# CONFIGURATION & GLOBAL VARIABLES
# ==============================================================================

# Associative array for exclusions
declare -A EXCLUSION_MAP
DELETE_LIMIT=200
ERROR_COUNT=0

# Environment Variables expected from Cloud Build
PROJECT_ID="${PROJECT_ID:-hpc-toolkit-dev}"
DRY_RUN="${DRY_RUN:-true}"
EXCLUSION_FILE="${EXCLUSION_FILE:-tools/exclusions.txt}"
CUTOFF_TIME="${CUTOFF_TIME:-$(date -d '2 hours ago' -u +%Y-%m-%dT%H:%M:%S%z)}"
IMAGE_AGE_DAYS="${IMAGE_AGE_DAYS:-60}"
CUTOFF_TIME_IMAGES="${CUTOFF_TIME_IMAGES:-$(date -d "$IMAGE_AGE_DAYS days ago" -u +%Y-%m-%dT%H:%M:%S%z)}"

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

log() {
    local level="$1"
    local message="$2"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [$level] $message"
}

check_dependencies() {
    local dependencies=("gcloud" "awk" "grep" "sort" "jq" "date")
    for cmd in "${dependencies[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log "ERROR" "Missing required dependency: $cmd"
            exit 1 # Dependencies are critical, we must exit immediately here.
        fi
    done
}

load_exclusions() {
    if [[ ! -f "$EXCLUSION_FILE" ]]; then
        log "ERROR" "Exclusion file not found: $EXCLUSION_FILE."
        exit 1
    fi

    log "INFO" "Loading exclusions from $EXCLUSION_FILE..."
    while IFS= read -r line || [[ -n "$line" ]]; do
        local trimmed_line
        trimmed_line=$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        if [[ -n "$trimmed_line" ]] && [[ "$trimmed_line" != \#* ]]; then
            EXCLUSION_MAP["$trimmed_line"]=1
        fi
    done < "$EXCLUSION_FILE"
}

is_excluded() {
    local resource_name="$1"
    local labels_str="${2:-}"

    if [[ -n "${EXCLUSION_MAP[$resource_name]:-}" ]]; then
        log "SKIP" "$resource_name (In Exclusion List)"
        return 0
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
                    if ! exp_seconds=$(date -d "$VAL + 1 day" +%s 2>/dev/null); then
                         log "WARNING" "$resource_name (Label: do-not-delete invalid date value: $VAL)"
                    else
                        local current_seconds
                        current_seconds=$(date +%s)
                        if [[ "$exp_seconds" -gt "$current_seconds" ]]; then
                            log "SKIP" "$resource_name (Label: do-not-delete=$VAL, valid until end of day)"
                            return 0 
                        else
                            log "INFO" "$resource_name (Label: do-not-delete=$VAL expired)"
                        fi
                    fi
                else
                    log "WARNING" "$resource_name (Label: do-not-delete invalid date format: $VAL, expected YYYY-MM-DD)"
                fi
                break
            fi
        done
    fi
    return 1
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

# ==============================================================================
# STANDARD PROCESSOR
# ==============================================================================

process_resources() {
    local label="$1"
    local list_command="$2"
    local delete_command_base="$3"
    local scope_type="$4"

    log "INFO" "--- Processing: $label (Limit: $DELETE_LIMIT) ---"

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
        if [[ $count -ge $DELETE_LIMIT ]]; then
            log "INFO" "Hit delete limit ($DELETE_LIMIT) for $label."
            break
        fi

        if is_excluded "$name" "${labels_str:-}"; then continue; fi

        local final_cmd="$delete_command_base \"$name\" --quiet"
        if [[ "$scope_type" != "none" && -n "$scope" ]]; then
            final_cmd="$final_cmd --$scope_type=\"$scope\""
        fi

        execute_delete "$label" "$name" "$final_cmd" "${scope:-(Global)}"
        ((count++)) || true
    done <<< "$resources"
}

# ==============================================================================
# SPECIFIC HANDLERS
# ==============================================================================

process_instance_templates() {
    log "INFO" "--- Processing: Instance Templates (Limit: $DELETE_LIMIT) ---"
    local templates
    if ! templates=$(gcloud compute instance-templates list \
        --project="$PROJECT_ID" \
        --filter="creationTimestamp < '$CUTOFF_TIME'" \
        --format="value(name, labels)" | sort); then
        log "ERROR" "Failed to list instance templates."
        ((ERROR_COUNT++)) || true
        return 0
    fi
    if [[ -z "$templates" ]]; then log "INFO" "No instance templates found matching criteria."; return 0; fi

    local count=0
    while IFS=$'\t' read -r name labels_str; do
        if [[ -z "$name" ]]; then continue; fi
        if [[ $count -ge $DELETE_LIMIT ]]; then log "INFO" "Hit delete limit ($DELETE_LIMIT) for Instance Templates."; break; fi
        if is_excluded "$name" "${labels_str:-}"; then continue; fi
        execute_delete "Instance Template" "$name" \
            "gcloud compute instance-templates delete \"$name\" --project=\"$PROJECT_ID\" --quiet" \
            "(Global)"
        ((count++)) || true
    done <<< "$templates"
}

process_addresses() {
    log "INFO" "--- Processing: Compute Addresses ---"
    process_resources "Regional Address" \
        "gcloud compute addresses list --project=\"$PROJECT_ID\" --filter=\"creationTimestamp < '$CUTOFF_TIME' AND region:*\" --format=\"value(name,region,labels)\" | sort" \
        "gcloud compute addresses delete --project=\"$PROJECT_ID\"" \
        "region"
    process_resources "Global Address" \
        "gcloud compute addresses list --project=\"$PROJECT_ID\" --filter=\"creationTimestamp < '$CUTOFF_TIME' AND NOT region:*\" --format=\"value[separator='t'](name, labels)\" | awk 'BEGIN{OFS=\"\t\"} {if (NF==1) print \$1, \"Global\", \"\"; else print \$1, \"Global\", \$2}' | sort" \
        "gcloud compute addresses delete --project=\"$PROJECT_ID\" --global" \
        "none"
}

process_vpc_peerings() {
    log "INFO" "--- Processing: VPC Peerings (Limit: $DELETE_LIMIT) ---"
    local networks_json
    if ! networks_json=$(gcloud compute networks list --project="$PROJECT_ID" --format="json"); then
        log "ERROR" "Failed to list networks."
        ((ERROR_COUNT++)) || true
        return 0
    fi
    if [[ -z "$networks_json" || "$networks_json" == "[]" ]]; then log "INFO" "No networks found in project."; return 0; fi

    local count=0
    while IFS= read -r net_obj; do
        if [[ $count -ge $DELETE_LIMIT ]]; then break; fi
        local net_name
        net_name=$(echo "$net_obj" | jq -r '.name')
        if [[ -z "$net_name" || "$net_name" == "null" ]]; then continue; fi

        local peerings_json
        peerings_json=$(echo "$net_obj" | jq -c '.peerings // []')
        if [[ "$peerings_json" == "[]" || "$peerings_json" == "null" ]]; then continue; fi

        while IFS= read -r peering_obj; do
            if [[ $count -ge $DELETE_LIMIT ]]; then break; fi
            local peering_name
            peering_name=$(echo "$peering_obj" | jq -r '.name')
            if [[ -z "$peering_name" || "$peering_name" == "null" ]]; then continue; fi

            if is_excluded "$peering_name" || is_excluded "$net_name"; then continue; fi

            local peer_network
            peer_network=$(echo "$peering_obj" | jq -r '.network // ""')
            local state
            state=$(echo "$peering_obj" | jq -r '.state // ""')

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
        done < <(echo "$peerings_json" | jq -c '.[]')
    done < <(echo "$networks_json" | jq -c '.[]')
    if [[ $count -ge $DELETE_LIMIT ]]; then log "INFO" "Hit delete limit ($DELETE_LIMIT) for VPC Peerings."; fi
    log "INFO" "Finished processing VPC Peerings. $count peerings actioned."
}

process_iam_deleted_members() {
    log "INFO" "--- Processing: IAM Role Bindings for Deleted SAs (Limit: $DELETE_LIMIT) ---"
    local policy_json
    if ! policy_json=$(gcloud projects get-iam-policy "$PROJECT_ID" --format=json); then
        log "ERROR" "Failed to get IAM policy."
        ((ERROR_COUNT++)) || true
        return 0
    fi
    local deleted_bindings
    deleted_bindings=$(echo "$policy_json" | jq -r '.bindings[] | .role as $r | .members[] | select(startswith("deleted:serviceAccount:")) | "\($r)\t\(.)"')
    if [[ -z "$deleted_bindings" ]]; then log "INFO" "No 'deleted:serviceAccount' bindings found."; return 0; fi

    local count=0
    while IFS=$'\t' read -r role member; do
        if [[ -z "$role" || -z "$member" ]]; then continue; fi
        if [[ $count -ge $DELETE_LIMIT ]]; then log "INFO" "Hit delete limit ($DELETE_LIMIT) for IAM Bindings."; break; fi
        
        local cmd="gcloud projects remove-iam-policy-binding \"$PROJECT_ID\" --member=\"$member\" --role=\"$role\" --condition=None --quiet"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log "DRY-RUN" "Would remove IAM binding: $member from role $role"
        else
            log "EXECUTE" "Removing IAM binding: $member from role $role"
            if ! eval "$cmd" >/dev/null; then
                log "ERROR" "Failed to remove binding"
                ((ERROR_COUNT++)) || true
            fi
        fi
        ((count++)) || true
    done <<< "$deleted_bindings"
}

process_vm_images() {
    log "INFO" "--- Processing: VM Images (Limit: $DELETE_LIMIT) ---"
    local images
    if ! images=$(gcloud compute images list --project="$PROJECT_ID" --no-standard-images \
        --format="value(name,creationTimestamp,labels)"); then
        log "ERROR" "Failed to list VM images"
        ((ERROR_COUNT++)) || true
        return 0
    fi

    if [[ -z "$images" ]]; then log "INFO" "No custom VM images found."; return 0; fi

    local cutoff_seconds
    # Using date check directly; if date fails, we handle it inside the loop
    if ! cutoff_seconds=$(date -d "$CUTOFF_TIME_IMAGES" +%s); then
        log "ERROR" "Failed to calculate cutoff time for images"
        ((ERROR_COUNT++)) || true
        return 0
    fi

    local count=0
    while IFS=$'\t' read -r name timestamp labels_str; do
        [[ -z "$name" ]] && continue
        if [[ $count -ge $DELETE_LIMIT ]]; then log "INFO" "Hit delete limit ($DELETE_LIMIT) for VM Images."; break; fi
        if is_excluded "$name" "${labels_str:-}"; then continue; fi

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
    done <<< "$images"
}

process_docker_images() {
    log "INFO" "--- Processing: Docker Images for 'test-runner' (Artifact Registry) (Limit: $DELETE_LIMIT) ---"
    local cutoff_date
    cutoff_date=$(date -u -d "14 days ago" '+%Y-%m-%dT%H:%M:%SZ')
    local cutoff_seconds
    if ! cutoff_seconds=$(date -u -d "$cutoff_date" +%s); then 
        log "ERROR" "Failed to calculate cutoff_seconds."
        ((ERROR_COUNT++)) || true
        return 0
    fi
    log "INFO" "Policy: Delete 'test-runner' images updated before $cutoff_date (Unix: $cutoff_seconds)"

    local location="us-central1"
    local repo_name="hpc-toolkit-repo"
    local package_name="test-runner"
    local full_package_url="${location}-docker.pkg.dev/${PROJECT_ID}/${repo_name}/${package_name}"
    
    local images_output
    # Use if ! to catch failure without exiting
    if ! images_output=$(gcloud artifacts docker images list "$full_package_url" --format="csv[no-heading](uri,updateTime)" --sort-by="updateTime" 2>/dev/null); then
        log "WARNING" "Failed to list images for $full_package_url (Repo might not exist or empty)"
        return 0
    fi
    if [[ -z "$images_output" ]]; then log "INFO" "  > No image versions found for $package_name."; return 0; fi

    local count=0
    while IFS=, read -r full_image_ref update_time; do
         if [[ -z "$full_image_ref" ]]; then continue; fi
         if [[ -z "$update_time" ]]; then continue; fi
         if [[ "$full_image_ref" != *"@sha256:"* ]]; then continue; fi

         local image_seconds
         if ! image_seconds=$(date -u -d "$update_time" +%s 2>/dev/null); then continue; fi

         if [[ $image_seconds -ge $cutoff_seconds ]]; then continue; 
         else
             if [[ $count -ge $DELETE_LIMIT ]]; then log "INFO" "Hit delete limit ($DELETE_LIMIT) for Docker Images."; break; fi
             if is_excluded "$package_name"; then continue; fi
             if is_excluded "$full_image_ref"; then continue; fi 

             execute_delete "Docker Image Version" "$full_image_ref" \
                 "gcloud artifacts docker images delete \"$full_image_ref\" --project=\"$PROJECT_ID\" --delete-tags --quiet" \
                 "(Updated: $update_time)"
             ((count++)) || true
         fi
    done <<< "$images_output"
    log "INFO" "Finished Docker Image processing for $package_name. $count images marked for deletion."
}

process_firewalls() {
    log "INFO" "--- Processing: Firewall Rules (Limit: $DELETE_LIMIT) ---"
    local fws
    if ! fws=$(gcloud compute firewall-rules list --project="$PROJECT_ID" \
        --filter="creationTimestamp < '$CUTOFF_TIME'" \
        --format="value(name,network,labels)" | sort); then
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
        if [[ $count -ge $DELETE_LIMIT ]]; then log "INFO" "Hit delete limit ($DELETE_LIMIT) for Firewall Rules."; break; fi
        if is_excluded "$name" "${labels_str:-}"; then continue; fi
        execute_delete "Firewall Rule" "$name" \
            "gcloud compute firewall-rules delete \"$name\" --project=\"$PROJECT_ID\" --quiet"
        ((count++)) || true
    done <<< "$fws"
}

process_filestore() {
    log "INFO" "--- Processing: Filestore Instances (Limit: $DELETE_LIMIT) ---"
    local fs_json
    if ! fs_json=$(gcloud filestore instances list --project="$PROJECT_ID" --filter="createTime < '$CUTOFF_TIME'" --format="json"); then
        log "ERROR" "Failed to list Filestore instances."
        ((ERROR_COUNT++)) || true
        return 0
    fi
    if [[ -z "$fs_json" || "$fs_json" == "[]" ]]; then log "INFO" "No Filestore instances found matching criteria."; return 0; fi

    local fs_list
    if ! fs_list=$(echo "$fs_json" | jq -r '.[] | select(.name) | "\(.name | split("/")[3])\t\(.name | split("/")[-1])\t\(.labels | to_entries | map("\(.key)=\(.value)") | join(";"))"'); then
        log "ERROR" "Failed to parse Filestore JSON with jq."
        ((ERROR_COUNT++)) || true
        return 0
    fi
    if [[ -z "$fs_list" ]]; then log "INFO" "No instances found after jq parsing."; return 0; fi

    local count=0
    while IFS=$'\t' read -r location name labels_str; do
        location=$(echo "$location" | awk '{$1=$1};1'); name=$(echo "$name" | awk '{$1=$1};1')
        if [[ -z "$location" || -z "$name" ]]; then continue; fi
        if [[ $count -ge $DELETE_LIMIT ]]; then log "INFO" "Hit delete limit ($DELETE_LIMIT) for Filestore."; break; fi
        if is_excluded "$name" "${labels_str:-}"; then continue; fi
        local delete_cmd="gcloud filestore instances delete \"$name\" --project=\"$PROJECT_ID\" --location=\"$location\" --quiet --force"
        execute_delete "Filestore" "$name" "$delete_cmd" "($location)"
        ((count++)) || true
    done <<< "$fs_list"
    log "INFO" "Finished processing Filestore instances. Attempted to delete $count."
}

process_subnetworks() {
    log "INFO" "--- Processing: Subnetworks (Limit: $DELETE_LIMIT) ---"
    local subnets
    if ! subnets=$(gcloud compute networks subnets list --project="$PROJECT_ID" --filter="creationTimestamp < '$CUTOFF_TIME'" --format="value(name,region,network,selfLink)"); then
        log "ERROR" "Failed to list subnets"
        ((ERROR_COUNT++)) || true
        return 0
    fi
    
    local count=0
    while IFS=$'\t' read -r name region network_uri self_link; do
        [[ -z "$name" ]] && continue
        local network_name=$(basename "$network_uri")
        if [[ "$network_name" == "default" ]]; then continue; fi
        if [[ $count -ge $DELETE_LIMIT ]]; then log "INFO" "Hit delete limit ($DELETE_LIMIT) for Subnetworks."; break; fi
        if is_excluded "$name"; then continue; fi

        # Note: listing dependents might fail, wrapping in error check not strictly necessary for deletion loop but good practice
        local dependents
        dependents=$(gcloud compute addresses list --project="$PROJECT_ID" --filter="purpose=GCE_ENDPOINT AND region=(\"$region\") AND subnetwork=(\"$self_link\")" --format="value(name)" 2>/dev/null || true)
        
        for addr in $dependents; do
             execute_delete "Dependent Address" "$addr" "gcloud compute addresses delete \"$addr\" --project=\"$PROJECT_ID\" --region=\"$region\" --quiet"
        done
        execute_delete "Subnetwork" "$name" "gcloud compute networks subnets delete \"$name\" --project=\"$PROJECT_ID\" --region=\"$region\" --quiet"
        ((count++)) || true
    done <<< "$subnets"
}

process_networks() {
    log "INFO" "--- Processing: VPC Networks (Limit: $DELETE_LIMIT) ---"
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
        if [[ $count -ge $DELETE_LIMIT ]]; then log "INFO" "Hit delete limit ($DELETE_LIMIT) for Networks."; break; fi
        if is_excluded "$name"; then continue; fi

        local routes
        routes=$(gcloud compute routes list --project="$PROJECT_ID" --filter="network=\"$self_link\"" --format="value(name)" 2>/dev/null || true)
        for r in $routes; do if ! is_excluded "$r"; then execute_delete "Dep. Route" "$r" "gcloud compute routes delete \"$r\" --project=\"$PROJECT_ID\" --quiet"; fi; done
        
        local fws
        fws=$(gcloud compute firewall-rules list --project="$PROJECT_ID" --filter="network=\"$self_link\"" --format="value(name)" 2>/dev/null || true)
        for fw in $fws; do if ! is_excluded "$fw"; then execute_delete "Dep. FW" "$fw" "gcloud compute firewall-rules delete \"$fw\" --project=\"$PROJECT_ID\" --quiet"; fi; done
        
        execute_delete "Network" "$name" "gcloud compute networks delete \"$name\" --project=\"$PROJECT_ID\" --quiet"
        ((count++)) || true
    done <<< "$networks"
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

main() {
    log "INFO" "STARTING RESOURCE CLEANUP: $PROJECT_ID"
    log "INFO" "Time Cutoff (General): $CUTOFF_TIME"
    log "INFO" "Time Cutoff (Images): $CUTOFF_TIME_IMAGES"
    log "INFO" "Delete Limit per Type: $DELETE_LIMIT"
    log "INFO" "DRY_RUN: $DRY_RUN"
    log "INFO" "Exclusion File: $EXCLUSION_FILE"

    check_dependencies
    load_exclusions

    # --- Phase 1: High Level Resources ---
    process_resources "GKE Cluster" \
        "gcloud container clusters list --project=\"$PROJECT_ID\" --filter=\"createTime < '$CUTOFF_TIME'\" --format=\"value(name,location,resourceLabels)\" | sort" \
        "gcloud container clusters delete --project=\"$PROJECT_ID\"" "location"
    process_instance_templates
    process_resources "Compute Instance" \
        "gcloud compute instances list --project=\"$PROJECT_ID\" --filter=\"creationTimestamp < '$CUTOFF_TIME'\" --format=\"value(name,zone,labels)\" | sort" \
        "gcloud compute instances delete --project=\"$PROJECT_ID\" --delete-disks=all" "zone"
    process_filestore

    # --- Phase 2: Images & Artifacts ---
    process_vm_images
    process_docker_images

    # --- Phase 3: Network Infrastructure ---
    process_resources "Cloud Router" \
        "gcloud compute routers list --project=\"$PROJECT_ID\" --filter=\"creationTimestamp < '$CUTOFF_TIME'\" --format=\"value(name,region,labels)\" | sort" \
        "gcloud compute routers delete --project=\"$PROJECT_ID\"" "region"
    process_firewalls
    process_addresses
    process_vpc_peerings
    process_resources "Zonal Disk" \
        "gcloud compute disks list --project=\"$PROJECT_ID\" --filter=\"creationTimestamp < '$CUTOFF_TIME' AND zone:*\" --format=\"value(name,zone,labels)\" | sort" \
        "gcloud compute disks delete --project=\"$PROJECT_ID\"" "zone"

    # --- Phase 4: Networking Hierarchies ---
    process_subnetworks
    process_networks

    # --- Phase 5: IAM Cleanup ---
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