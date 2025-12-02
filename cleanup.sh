#!/bin/bash

# ==============================================================================
# CONFIGURATION & GLOBAL VARIABLES
# ==============================================================================

set -u
set -o pipefail

# Output Redirection
LOG_FILE="template.txt"
exec >> "$LOG_FILE" 2>&1

PROJECT_ID="hpc-toolkit-dev"
DRY_RUN="false"  # Set to "false" to actually delete
EXCLUSION_FILE="exclusions.txt"
DELETE_LIMIT=200
PROTECTED_SUBSTRING="topology"

# Service Account Config
SA_DELETE_PREFIX="test-sa-" 

# VM Image Config
IMAGE_AGE_DAYS=60

# Time Calculations
# Standard Resource Cutoff (1 hour buffer)
CUTOFF_TIME=$(date -d "5 hours ago" -u +%Y-%m-%dT%H:%M:%S%z)
# Image Cutoff (60 days ago)
CUTOFF_TIME_IMAGES=$(date -d "$IMAGE_AGE_DAYS days ago" -u +%Y-%m-%dT%H:%M:%S%z)

# Associative array for exclusions
declare -A EXCLUSION_MAP

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
            exit 1
        fi
    done
}

load_exclusions() {
    if [[ ! -f "$EXCLUSION_FILE" ]]; then
        log "WARNING" "Exclusion file not found: $EXCLUSION_FILE. Proceeding without exclusions."
        return
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
    if [[ "$resource_name" == *"$PROTECTED_SUBSTRING"* ]]; then
        log "SKIP" "$resource_name (Protected Substring)"
        return 0
    fi
    if [[ -n "${EXCLUSION_MAP[$resource_name]:-}" ]]; then
        log "SKIP" "$resource_name (In Exclusion List)"
        return 0
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
    local scope_type="$4" # location, zone, region, or none

    log "INFO" "--- Processing: $label (Limit: $DELETE_LIMIT) ---"

    local resources
    if ! resources=$(eval "$list_command"); then
        log "ERROR" "Failed to list $label"
        return
    fi

    if [[ -z "$resources" ]]; then
        log "INFO" "No $label found matching criteria."
        return
    fi

    local count=0
    while read -r line; do
        [[ -z "$line" ]] && continue
        local name scope
        read -r name scope <<< "$line" 

        if [[ -z "$name" ]]; then continue; fi
        
        # --- LIMIT CHECK ---
        if [[ $count -ge $DELETE_LIMIT ]]; then 
            log "INFO" "Hit delete limit ($DELETE_LIMIT) for $label."
            break
        fi

        if is_excluded "$name"; then continue; fi

        local final_cmd="$delete_command_base \"$name\" --quiet"
        if [[ "$scope_type" != "none" && -n "$scope" ]]; then
            final_cmd="$final_cmd --$scope_type=\"$scope\""
        fi

        execute_delete "$label" "$name" "$final_cmd" "${scope:-(Global)}"
        ((count++))
    done <<< "$resources"
}

# ==============================================================================
# SPECIFIC HANDLERS
# ==============================================================================

process_instance_templates() {
    log "INFO" "--- Processing: Instance Templates (Limit: $DELETE_LIMIT) ---"

    # List templates created before CUTOFF_TIME
    local templates
    if ! templates=$(gcloud compute instance-templates list \
        --project="$PROJECT_ID" \
        --filter="creationTimestamp < '$CUTOFF_TIME'" \
        --format="value(name)" | sort); then
        log "ERROR" "Failed to list instance templates."
        return 1
    fi

    if [[ -z "$templates" ]]; then
        log "INFO" "No instance templates found matching criteria."
        return
    fi

    local count=0
    while read -r name; do
        if [[ -z "$name" ]]; then continue; fi

        # --- LIMIT CHECK ---
        if [[ $count -ge $DELETE_LIMIT ]]; then
            log "INFO" "Hit delete limit ($DELETE_LIMIT) for Instance Templates."
            break
        fi

        if is_excluded "$name"; then continue; fi

        execute_delete "Instance Template" "$name" \
            "gcloud compute instance-templates delete \"$name\" --project=\"$PROJECT_ID\" --quiet" \
            "(Global)"
        
        ((count++))
    done <<< "$templates"
}

process_addresses() {
    log "INFO" "--- Processing: Compute Addresses ---"
    
    # These use the Standard Processor, so the limit is handled inside process_resources
    process_resources "Regional Address" \
        "gcloud compute addresses list --project=\"$PROJECT_ID\" --filter=\"creationTimestamp < '$CUTOFF_TIME' AND region:*\" --format=\"value(name,region)\" | sort" \
        "gcloud compute addresses delete --project=\"$PROJECT_ID\"" \
        "region"

    process_resources "Global Address" \
        "gcloud compute addresses list --project=\"$PROJECT_ID\" --filter=\"creationTimestamp < '$CUTOFF_TIME' AND NOT region:*\" --format=\"value(name)\" | sort" \
        "gcloud compute addresses delete --project=\"$PROJECT_ID\" --global" \
        "none"
}


process_vpc_peerings() {
    log "INFO" "--- Processing: VPC Peerings (Limit: $DELETE_LIMIT) ---"

    local networks_json
    if ! networks_json=$(gcloud compute networks list --project="$PROJECT_ID" --format="json"); then
        log "ERROR" "Failed to list networks."
        return 1
    fi

    if [[ -z "$networks_json" || "$networks_json" == "[]" ]]; then
        log "INFO" "No networks found in project."
        return
    fi

    local count=0

    # Use process substitution <(...) to avoid subshell issues so 'count' updates correctly
    while IFS= read -r net_obj; do
        if [[ $count -ge $DELETE_LIMIT ]]; then break; fi

        local net_name
        net_name=$(echo "$net_obj" | jq -r '.name')
        
        if [[ -z "$net_name" || "$net_name" == "null" ]]; then continue; fi

        # log "DEBUG" "Checking network: $net_name"

        # Check for peerings array inside the network object
        local peerings_json
        peerings_json=$(echo "$net_obj" | jq -c '.peerings // []')

        # If empty array or null, skip
        if [[ "$peerings_json" == "[]" || "$peerings_json" == "null" ]]; then
            continue
        fi

        # Inner loop for peerings
        while IFS= read -r peering_obj; do
            if [[ $count -ge $DELETE_LIMIT ]]; then break; fi

            local peering_name
            peering_name=$(echo "$peering_obj" | jq -r '.name')

            if [[ -z "$peering_name" || "$peering_name" == "null" ]]; then
                log "DEBUG" "  Skipping peering with no name"
                continue
            fi

            local peer_network
            peer_network=$(echo "$peering_obj" | jq -r '.network // ""')
            local state
            state=$(echo "$peering_obj" | jq -r '.state // ""')

            if is_excluded "$peering_name" || is_excluded "$net_name"; then
                continue
            fi

            if [[ "$peering_name" == "servicenetworking-googleapis-com" ]]; then
                log "INFO" "    [ACTION] Deleting Service Networking peering on: $net_name"
                execute_delete "Service Peering" "$peering_name" \
                    "gcloud services vpc-peerings delete --service=servicenetworking.googleapis.com --network=\"$net_name\" --project=\"$PROJECT_ID\" --quiet" \
                    "(Network: $net_name)"
                ((count++))
            elif [[ "$peering_name" == filestore-peer-* ]]; then
                log "INFO" "    [SKIP] Managed Filestore peering: $peering_name on $net_name. This is tied to a Filestore instance lifecycle."
                continue
            elif [[ "$peer_network" == *"/global/networks/servicenetworking" ]]; then
                log "INFO" "    [SKIP] Reverse Service Networking peering: $peering_name on $net_name"
                continue
            else
                # Standard VPC Peering
                log "INFO" "    [ACTION] Deleting Standard VPC peering: $peering_name on: $net_name (State: $state)"
                execute_delete "VPC Peering" "$peering_name" \
                   "gcloud compute networks peerings delete \"$peering_name\" --network=\"$net_name\" --project=\"$PROJECT_ID\" --quiet" \
                   "(Network: $net_name, State: $state)"
                ((count++))
            fi
        done < <(echo "$peerings_json" | jq -c '.[]') 

    done < <(echo "$networks_json" | jq -c '.[]') 

    if [[ $count -ge $DELETE_LIMIT ]]; then
        log "INFO" "Hit delete limit ($DELETE_LIMIT) for VPC Peerings."
    fi
    log "INFO" "Finished processing VPC Peerings. $count peerings actioned."
}

process_service_accounts() {
    log "INFO" "--- Processing: Service Accounts (Prefix: $SA_DELETE_PREFIX) ---"
    
    # We use 'head -n' here to enforce the limit at the list level
    local sas
    sas=$(gcloud iam service-accounts list --project="$PROJECT_ID" \
        --filter="email ~ ^$SA_DELETE_PREFIX" \
        --format="value(email)" | head -n "$DELETE_LIMIT")

    if [[ -z "$sas" ]]; then
        log "INFO" "No Service Accounts found matching prefix."
        return
    fi

    for email in $sas; do
        if is_excluded "$email"; then continue; fi
        execute_delete "Service Account" "$email" \
            "gcloud iam service-accounts delete \"$email\" --project=\"$PROJECT_ID\" --quiet"
    done
}

process_iam_deleted_members() {
    log "INFO" "--- Processing: IAM Role Bindings for Deleted SAs (Limit: $DELETE_LIMIT) ---"

    local policy_json
    if ! policy_json=$(gcloud projects get-iam-policy "$PROJECT_ID" --format=json); then
        log "ERROR" "Failed to get IAM policy."
        return
    fi

    local deleted_bindings
    deleted_bindings=$(echo "$policy_json" | jq -r '.bindings[] | .role as $r | .members[] | select(startswith("deleted:serviceAccount:")) | "\($r)\t\(.)"')

    if [[ -z "$deleted_bindings" ]]; then
        log "INFO" "No 'deleted:serviceAccount' bindings found."
        return
    fi

    local count=0

    while IFS=$'\t' read -r role member; do
        if [[ -z "$role" || -z "$member" ]]; then continue; fi

        # --- LIMIT CHECK ---
        if [[ $count -ge $DELETE_LIMIT ]]; then
            log "INFO" "Hit delete limit ($DELETE_LIMIT) for IAM Bindings."
            break
        fi
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log "DRY-RUN" "Would remove IAM binding: $member from role $role"
        else
            log "EXECUTE" "Removing IAM binding: $member from role $role"
            gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
                --member="$member" --role="$role" --condition=None --quiet >/dev/null || log "ERROR" "Failed to remove binding"
        fi
        
        ((count++))
    done <<< "$deleted_bindings"
}

process_vm_images() {
    log "INFO" "--- Processing: VM Images (Limit: $DELETE_LIMIT) ---"

    local images
    images=$(gcloud compute images list --project="$PROJECT_ID" --no-standard-images \
        --format="value(name,creationTimestamp)")
    
    if [[ -z "$images" ]]; then
        log "INFO" "No custom VM images found."
        return
    fi

    local cutoff_seconds
    cutoff_seconds=$(date -d "$CUTOFF_TIME_IMAGES" +%s)
    local count=0

    while read -r name timestamp; do
        [[ -z "$name" ]] && continue
        
        # --- LIMIT CHECK ---
        if [[ $count -ge $DELETE_LIMIT ]]; then
            log "INFO" "Hit delete limit ($DELETE_LIMIT) for VM Images."
            break
        fi

        if is_excluded "$name"; then continue; fi

        local ts_seconds
        if ! ts_seconds=$(date -d "$timestamp" +%s 2>/dev/null); then
            log "WARNING" "Could not parse timestamp '$timestamp' for image $name. Skipping."
            continue
        fi

        if [[ $ts_seconds -lt $cutoff_seconds ]]; then
             execute_delete "VM Image" "$name" \
                "gcloud compute images delete \"$name\" --project=\"$PROJECT_ID\" --quiet"
             ((count++))
        fi

    done <<< "$images"
}

process_docker_images() {
    log "INFO" "--- Processing: Docker Images for 'test-runner' (Artifact Registry) (Limit: $DELETE_LIMIT) ---"

    # 1. Calculate Cutoff (14 Days Ago) using UTC
    local cutoff_date
    cutoff_date=$(date -u -d "14 days ago" '+%Y-%m-%dT%H:%M:%SZ')
    local cutoff_seconds
    if ! cutoff_seconds=$(date -u -d "$cutoff_date" +%s); then
        log "ERROR" "Failed to calculate cutoff_seconds."
        return 1
    fi
    log "INFO" "Policy: Delete 'test-runner' images updated before $cutoff_date (Unix: $cutoff_seconds)"

    local location="us-central1"
    local repo_name="hpc-toolkit-repo"
    local package_name="test-runner"
    local full_package_url="${location}-docker.pkg.dev/${PROJECT_ID}/${repo_name}/${package_name}"

    log "INFO" "Scanning Target Package: $full_package_url"

    # 5. List image versions for "test-runner" using CSV format
    local images_output
    if ! images_output=$(gcloud artifacts docker images list "$full_package_url" \
        --format="csv[no-heading](uri,updateTime)" \
        --sort-by="updateTime"); then
        log "WARNING" "Failed to list images for $full_package_url"
        return 1
    fi

    if [[ -z "$images_output" ]]; then
        log "INFO" "  > No image versions found for $package_name."
        return
    fi

    local count=0
    # 6. Iterate Images Line by Line (using CSV parsing)
    while IFS=, read -r full_image_ref update_time; do
         if [[ -z "$full_image_ref" ]]; then continue; fi

         # Sanity check: Ensure we have a valid timestamp
         if [[ -z "$update_time" ]]; then
             log "DEBUG" "  Skipping line, missing timestamp for: $full_image_ref"
             continue
         fi

         # We only care about images with a digest in the URI (@sha256:...)
         if [[ "$full_image_ref" != *"@sha256:"* ]]; then
             # log "DEBUG" "  Skipping URI without digest: $full_image_ref"
             continue
         fi

         # --- TIME CHECK ---
         local image_seconds
         if ! image_seconds=$(date -u -d "$update_time" +%s 2>/dev/null); then
             log "WARNING" "  Could not parse date '$update_time' for $full_image_ref. Skipping."
             continue
         fi

         if [[ $image_seconds -ge $cutoff_seconds ]]; then
             log "INFO" "  [KEEP] .../test-runner... (Updated: $update_time) - Too new"
         else
             # --- DELETE LOGIC ---
             if [[ $count -ge $DELETE_LIMIT ]]; then
                 log "INFO" "Hit delete limit ($DELETE_LIMIT) for Docker Images."
                 break # Break the loop, don't exit script
             fi

             if is_excluded "$package_name"; then
                 log "INFO" "  [SKIP] $package_name is excluded"
                 continue
             fi

             log "INFO" "  [DELETE] $full_image_ref (Updated: $update_time)"

             execute_delete "Docker Image Version" "$full_image_ref" \
                 "gcloud artifacts docker images delete \"$full_image_ref\" --project=\"$PROJECT_ID\" --delete-tags --quiet" \
                 "(Updated: $update_time)"
             ((count++))
         fi
    done <<< "$images_output"
    
    log "INFO" "Finished Docker Image processing for $package_name. $count images marked for deletion."
}


process_firewalls() {
    log "INFO" "--- Processing: Firewall Rules (Limit: $DELETE_LIMIT) ---"
    
    local fws
    fws=$(gcloud compute firewall-rules list --project="$PROJECT_ID" \
        --filter="creationTimestamp < '$CUTOFF_TIME'" \
        --format="value(name,network)" | sort)

    if [[ -z "$fws" ]]; then
        log "INFO" "No Firewall Rules found matching criteria."
        return
    fi

    local count=0
    while read -r name network_uri; do
        [[ -z "$name" ]] && continue

        # --- PROTECT DEFAULT NETWORK ---
        local network_name
        network_name=$(basename "$network_uri")
        if [[ "$network_name" == "default" ]]; then continue; fi

        # --- LIMIT CHECK ---
        if [[ $count -ge $DELETE_LIMIT ]]; then
            log "INFO" "Hit delete limit ($DELETE_LIMIT) for Firewall Rules."
            break
        fi

        if is_excluded "$name"; then continue; fi

        execute_delete "Firewall Rule" "$name" \
            "gcloud compute firewall-rules delete \"$name\" --project=\"$PROJECT_ID\" --quiet"
        
        ((count++))

    done <<< "$fws"
}

process_filestore() {
    log "INFO" "--- Processing: Filestore Instances (Limit: $DELETE_LIMIT) ---"

    # 1. Fetch JSON output for robust parsing
    local fs_json
    if ! fs_json=$(gcloud filestore instances list \
        --project="$PROJECT_ID" \
        --filter="createTime < '$CUTOFF_TIME'" \
        --format="json"); then # Removed 2>/dev/null to see gcloud errors
        log "ERROR" "Failed to list Filestore instances."
        return 1
    fi

    if [[ -z "$fs_json" || "$fs_json" == "[]" ]]; then
        log "INFO" "No Filestore instances found matching criteria."
        return
    fi


    # 2. Extract Location and Name using jq
    local fs_list
    if ! fs_list=$(echo "$fs_json" | jq -r '.[] | select(.name) | "\(.name | split("/")[3])\t\(.name | split("/")[-1])"'); then
        log "ERROR" "Failed to parse Filestore JSON with jq."
        return 1
    fi

    if [[ -z "$fs_list" ]]; then
        log "INFO" "No instances found after jq parsing."
        return
    fi

    local count=0

    # 3. Iterate
    while IFS=$'\t' read -r location name; do
        # Trim potential whitespace
        location=$(echo "$location" | awk '{$1=$1};1')
        name=$(echo "$name" | awk '{$1=$1};1')

        if [[ -z "$location" || -z "$name" ]]; then
             log "DEBUG" "Skipping line with empty fields: location='${location}', name='${name}'"
             continue
        fi

        log "DEBUG" "Processing Instance: Name='${name}', Location='${location}'"

        # --- LIMIT CHECK ---
        if [[ $count -ge $DELETE_LIMIT ]]; then
            log "INFO" "Hit delete limit ($DELETE_LIMIT) for Filestore."
            break
        fi

        if is_excluded "$name"; then
            log "INFO" "Skipping excluded Filestore: $name"
            continue
        fi

        # Construct delete command with explicit location
        local delete_cmd="gcloud filestore instances delete \"$name\" --project=\"$PROJECT_ID\" --location=\"$location\" --quiet --force"

        execute_delete "Filestore" "$name" "$delete_cmd" "($location)"

        ((count++))

    done <<< "$fs_list"

    log "INFO" "Finished processing Filestore instances. Attempted to delete $count."
}

process_subnetworks() {
    log "INFO" "--- Processing: Subnetworks (Limit: $DELETE_LIMIT) ---"
    
    local subnets
    subnets=$(gcloud compute networks subnets list --project="$PROJECT_ID" --filter="creationTimestamp < '$CUTOFF_TIME'" --format="value(name,region,network,selfLink)")
    
    local count=0
    while IFS=$'\t' read -r name region network_uri self_link; do
        [[ -z "$name" ]] && continue
        
        # --- PROTECT DEFAULT NETWORK ---
        local network_name=$(basename "$network_uri")
        if [[ "$network_name" == "default" ]]; then continue; fi
        
        # --- LIMIT CHECK ---
        if [[ $count -ge $DELETE_LIMIT ]]; then 
            log "INFO" "Hit delete limit ($DELETE_LIMIT) for Subnetworks."
            break
        fi

        if is_excluded "$name"; then continue; fi

        local dependents=$(gcloud compute addresses list --project="$PROJECT_ID" --filter="purpose=GCE_ENDPOINT AND region=(\"$region\") AND subnetwork=(\"$self_link\")" --format="value(name)")
        for addr in $dependents; do
             execute_delete "Dependent Address" "$addr" "gcloud compute addresses delete \"$addr\" --project=\"$PROJECT_ID\" --region=\"$region\" --quiet"
        done

        execute_delete "Subnetwork" "$name" "gcloud compute networks subnets delete \"$name\" --project=\"$PROJECT_ID\" --region=\"$region\" --quiet"
        ((count++))
    done <<< "$subnets"
}

process_networks() {
    log "INFO" "--- Processing: VPC Networks (Limit: $DELETE_LIMIT) ---"
    
    local networks
    networks=$(gcloud compute networks list --project="$PROJECT_ID" --filter="creationTimestamp < '$CUTOFF_TIME'" --format="value(name,selfLink)")
    
    local count=0
    while IFS=$'\t' read -r name self_link; do
        [[ -z "$name" ]] && continue

        # --- PROTECT DEFAULT NETWORK ---
        if [[ "$name" == "default" ]]; then continue; fi
        
        # --- LIMIT CHECK ---
        if [[ $count -ge $DELETE_LIMIT ]]; then 
            log "INFO" "Hit delete limit ($DELETE_LIMIT) for Networks."
            break
        fi

        if is_excluded "$name"; then continue; fi

        echo "$name $self_link"
        local routes=$(gcloud compute routes list --project="$PROJECT_ID" --filter="network=\"$self_link\"" --format="value(name)")
        for r in $routes; do execute_delete "Dep. Route" "$r" "gcloud compute routes delete \"$r\" --project=\"$PROJECT_ID\" --quiet"; done

        local fws=$(gcloud compute firewall-rules list --project="$PROJECT_ID" --filter="network=\"$self_link\"" --format="value(name)")
        for fw in $fws; do execute_delete "Dep. FW" "$fw" "gcloud compute firewall-rules delete \"$fw\" --project=\"$PROJECT_ID\" --quiet"; done

        execute_delete "Network" "$name" "gcloud compute networks delete \"$name\" --project=\"$PROJECT_ID\" --quiet"
        ((count++))
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
    
    check_dependencies
    load_exclusions

    # --- Phase 1: High Level Resources ---
    # process_service_accounts 
    
    # process_resources "GKE Cluster" \
    #     "gcloud container clusters list --project=\"$PROJECT_ID\" --filter=\"createTime < '$CUTOFF_TIME'\" --format=\"value(name,location)\" | sort" \
    #     "gcloud container clusters delete --project=\"$PROJECT_ID\"" "location"

    process_instance_templates

    # process_resources "Compute Instance" \
    #     "gcloud compute instances list --project=\"$PROJECT_ID\" --filter=\"creationTimestamp < '$CUTOFF_TIME'\" --format=\"value(name,zone)\" | sort" \
    #     "gcloud compute instances delete --project=\"$PROJECT_ID\"" "zone"

    # process_filestore
    # # --- Phase 2: Images & Artifacts ---
    # process_vm_images
    # process_docker_images

    # --- Phase 3: Network Infrastructure ---
    # process_resources "Cloud Router" \
    #     "gcloud compute routers list --project=\"$PROJECT_ID\" --filter=\"creationTimestamp < '$CUTOFF_TIME'\" --format=\"value(name,region)\" | sort" \
    #     "gcloud compute routers delete --project=\"$PROJECT_ID\"" "region"
    
    # process_firewalls

    # process_addresses 
    # process_vpc_peerings 
    
    # process_resources "Zonal Disk" \
    #     "gcloud compute disks list --project=\"$PROJECT_ID\" --filter=\"creationTimestamp < '$CUTOFF_TIME' AND zone:*\" --format=\"value(name,zone)\" | sort" \
    #     "gcloud compute disks delete --project=\"$PROJECT_ID\"" "zone"

    # # --- Phase 4: Networking Hierarchies ---
    # process_subnetworks
    # process_networks

    # # --- Phase 5: IAM Cleanup ---
    # process_iam_deleted_members

    log "INFO" "CLEANUP RUN FINISHED"
}

main