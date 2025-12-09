/**
  * Copyright 2023 Google LLC
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *
  *      http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */

terraform {
  backend "gcs" {
    bucket = "simranka"
    prefix = "a3mega-slurm/deletion-test/cluster"
  }
}

module "data-bucket" {
  source          = "./modules/embedded/modules/file-system/cloud-storage-bucket"
  deployment_name = var.deployment_name
  labels          = var.labels
  local_mount     = "/gcs"
  mount_options   = "defaults,rw,_netdev,implicit_dirs,allow_other,implicit_dirs,file_mode=777,dir_mode=777"
  project_id      = var.project_id
  random_suffix   = true
  region          = var.region
}

module "gpunets" {
  source                  = "./modules/embedded/modules/network/multivpc"
  deployment_name         = var.deployment_name
  global_ip_address_range = "10.0.0.0/9"
  network_count           = 8
  network_name_prefix     = "${var.deployment_name}-gpunet"
  project_id              = var.project_id
  region                  = var.region
  subnetwork_cidr_suffix  = 20
}

module "private_service_access" {
  source     = "./modules/embedded/community/modules/network/private-service-access"
  labels     = var.labels
  network_id = var.network_id_sysnet
  project_id = var.project_id
}

module "homefs" {
  source       = "./modules/embedded/modules/file-system/filestore"
  connect_mode = module.private_service_access.connect_mode
  deletion_protection = {
    enabled = true
    reason  = "Avoid data loss"
  }
  deployment_name   = var.deployment_name
  filestore_tier    = "HIGH_SCALE_SSD"
  labels            = var.labels
  local_mount       = "/home"
  mount_options     = "defaults,hard"
  network_id        = var.network_id_sysnet
  project_id        = var.project_id
  region            = var.region
  reserved_ip_range = module.private_service_access.reserved_ip_range
  size_gb           = 10240
  zone              = var.zone
}

module "debug_nodeset" {
  source                 = "./modules/embedded/community/modules/compute/schedmd-slurm-gcp-v6-nodeset"
  disk_size_gb           = var.disk_size_gb
  instance_image         = var.instance_image
  labels                 = var.labels
  machine_type           = "n2-standard-2"
  name                   = "debug_nodeset"
  node_count_dynamic_max = 4
  node_count_static      = 0
  project_id             = var.project_id
  region                 = var.region
  subnetwork_self_link   = var.subnetwork_self_link_sysnet
  zone                   = var.zone
}

module "debug_partition" {
  source         = "./modules/embedded/community/modules/compute/schedmd-slurm-gcp-v6-partition"
  exclusive      = false
  nodeset        = flatten([module.debug_nodeset.nodeset])
  partition_name = "debug"
}

module "a3mega_startup" {
  source          = "./modules/embedded/modules/scripts/startup-script"
  deployment_name = var.deployment_name
  docker = {
    daemon_config  = "{\n  \"data-root\": \"${var.localssd_mountpoint}/docker\"\n}\n"
    enabled        = true
    world_writable = true
  }
  labels = var.labels
  local_ssd_filesystem = {
    mountpoint  = var.localssd_mountpoint
    permissions = "1777"
  }
  project_id = var.project_id
  region     = var.region
  runners = [{
    content     = "---\n- name: Configure Slurm to depend upon aperture devices\n  hosts: all\n  become: true\n  vars: {}\n  tasks:\n  - name: Ensure slurmd starts after aperture devices are ready\n    ansible.builtin.copy:\n      dest: /etc/systemd/system/slurmd.service.d/aperture.conf\n      owner: root\n      group: root\n      mode: 0o644\n      content: |\n        [Service]\n        ExecCondition=/usr/bin/test -d /dev/aperture_devices/\n    notify: Reload SystemD\n  handlers:\n  - name: Reload SystemD\n    ansible.builtin.systemd:\n      daemon_reload: true\n"
    destination = "slurm_aperture.yml"
    type        = "ansible-local"
    }, {
    content     = "---\n- name: Enable NVIDIA DCGM on GPU nodes\n  hosts: all\n  become: true\n  vars:\n    enable_ops_agent: ${var.enable_ops_agent}\n    enable_nvidia_dcgm: ${var.enable_nvidia_dcgm}\n    enable_nvidia_persistenced: ${var.enable_nvidia_persistenced}\n  tasks:\n  - name: Update Ops Agent configuration\n    ansible.builtin.blockinfile:\n      path: /etc/google-cloud-ops-agent/config.yaml\n      insertafter: EOF\n      block: |\n        metrics:\n          receivers:\n            dcgm:\n              type: dcgm\n          service:\n            pipelines:\n              dcgm:\n                receivers:\n                  - dcgm\n    notify:\n    - Restart Google Cloud Ops Agent\n  handlers:\n  - name: Restart Google Cloud Ops Agent\n    ansible.builtin.service:\n      name: google-cloud-ops-agent.service\n      state: \"{{ 'restarted' if enable_ops_agent else 'stopped' }}\"\n      enabled: \"{{ enable_ops_agent }}\"\n  post_tasks:\n  - name: Enable Google Cloud Ops Agent\n    ansible.builtin.service:\n      name: google-cloud-ops-agent.service\n      state: \"{{ 'started' if enable_ops_agent else 'stopped' }}\"\n      enabled: \"{{ enable_ops_agent }}\"\n  - name: Enable NVIDIA DCGM\n    ansible.builtin.service:\n      name: nvidia-dcgm.service\n      state: \"{{ 'started' if enable_nvidia_dcgm else 'stopped' }}\"\n      enabled: \"{{ enable_nvidia_dcgm }}\"\n  - name: Enable NVIDIA Persistence Daemon\n    ansible.builtin.service:\n      name: nvidia-persistenced.service\n      state: \"{{ 'started' if enable_nvidia_persistenced else 'stopped' }}\"\n      enabled: \"{{ enable_nvidia_persistenced }}\"\n"
    destination = "enable_dcgm.yml"
    type        = "ansible-local"
  }]
}

module "a3mega_nodeset" {
  source              = "./modules/embedded/community/modules/compute/schedmd-slurm-gcp-v6-nodeset"
  additional_networks = flatten([module.gpunets.additional_networks])
  advanced_machine_features = {
    threads_per_core = null
  }
  bandwidth_tier = "gvnic_enabled"
  disk_size_gb   = var.disk_size_gb
  disk_type      = "pd-ssd"
  dws_flex = {
    enabled = var.a3mega_dws_flex_enabled
  }
  enable_public_ips = false
  enable_spot_vm    = var.a3mega_enable_spot_vm
  instance_image    = var.instance_image
  labels            = var.labels
  machine_type      = "a3-megagpu-8g"
  name              = "a3mega_nodeset"
  node_conf = {
    CoresPerSocket = 52
    ThreadsPerCore = 2
  }
  node_count_dynamic_max = 0
  node_count_static      = var.a3mega_cluster_size
  on_host_maintenance    = "TERMINATE"
  project_id             = var.project_id
  region                 = var.region
  reservation_name       = var.a3mega_reservation_name
  startup_script         = module.a3mega_startup.startup_script
  subnetwork_self_link   = var.subnetwork_self_link_sysnet
  zone                   = var.zone
}

module "a3mega_partition" {
  source     = "./modules/embedded/community/modules/compute/schedmd-slurm-gcp-v6-partition"
  exclusive  = false
  is_default = true
  nodeset    = flatten([module.a3mega_nodeset.nodeset])
  partition_conf = {
    OverSubscribe  = "EXCLUSIVE"
    ResumeTimeout  = 900
    SuspendTimeout = 600
  }
  partition_name = var.a3mega_partition_name
}

module "controller_startup" {
  source          = "./modules/embedded/modules/scripts/startup-script"
  deployment_name = var.deployment_name
  labels          = var.labels
  project_id      = var.project_id
  region          = var.region
  runners = [{
    content     = "#!/bin/bash\nSLURM_ROOT=/opt/apps/adm/slurm\nmkdir -m 0755 -p \"$${SLURM_ROOT}/scripts\"\nmkdir -p \"$${SLURM_ROOT}/partition-${var.a3mega_partition_name}-prolog_slurmd.d\"\nmkdir -p \"$${SLURM_ROOT}/partition-${var.a3mega_partition_name}-epilog_slurmd.d\"\nmkdir -p \"$${SLURM_ROOT}/prolog_slurmd.d\"\nmkdir -p \"$${SLURM_ROOT}/epilog_slurmd.d\"\n# enable the use of password-free sudo within Slurm jobs on all compute nodes\n# feature is restricted to users with OS Admin Login IAM role\n# https://cloud.google.com/iam/docs/understanding-roles#compute.osAdminLogin\ncurl -s -o \"$${SLURM_ROOT}/scripts/sudo-oslogin\" \\\n    https://raw.githubusercontent.com/GoogleCloudPlatform/slurm-gcp/master/tools/prologs-epilogs/sudo-oslogin\nchmod 0755 \"$${SLURM_ROOT}/scripts/sudo-oslogin\"\nln -s \"$${SLURM_ROOT}/scripts/sudo-oslogin\" \"$${SLURM_ROOT}/prolog_slurmd.d/sudo-oslogin.prolog_slurmd\"\nln -s \"$${SLURM_ROOT}/scripts/sudo-oslogin\" \"$${SLURM_ROOT}/epilog_slurmd.d/sudo-oslogin.epilog_slurmd\"\ncurl -s -o \"$${SLURM_ROOT}/scripts/rxdm\" \\\n    https://raw.githubusercontent.com/GoogleCloudPlatform/slurm-gcp/master/tools/prologs-epilogs/receive-data-path-manager-mega\nchmod 0755 \"$${SLURM_ROOT}/scripts/rxdm\"\nln -s \"$${SLURM_ROOT}/scripts/rxdm\" \"$${SLURM_ROOT}/partition-${var.a3mega_partition_name}-prolog_slurmd.d/rxdm.prolog_slurmd\"\nln -s \"$${SLURM_ROOT}/scripts/rxdm\" \"$${SLURM_ROOT}/partition-${var.a3mega_partition_name}-epilog_slurmd.d/rxdm.epilog_slurmd\"\n# enable a GPU health check that runs at the completion of all jobs on A3mega nodes\nln -s \"/slurm/scripts/tools/gpu-test\" \"$${SLURM_ROOT}/partition-${var.a3mega_partition_name}-epilog_slurmd.d/gpu-test.epilog_slurmd\"\n"
    destination = "stage_scripts.sh"
    type        = "shell"
    }, {
    content     = "#!/bin/bash\n# reset enroot to defaults of files under /home and running under /run\n# allows basic enroot testing with reduced I/O performance\nrm -f /etc/enroot/enroot.conf\n"
    destination = "reset_enroot.sh"
    type        = "shell"
  }]
}

module "slurm_login" {
  source                  = "./modules/embedded/community/modules/scheduler/schedmd-slurm-gcp-v6-login"
  disk_size_gb            = var.disk_size_gb
  disk_type               = "pd-balanced"
  enable_login_public_ips = var.enable_login_public_ips
  instance_image          = var.instance_image
  labels                  = var.labels
  machine_type            = "c2-standard-4"
  name_prefix             = "login"
  project_id              = var.project_id
  region                  = var.region
  subnetwork_self_link    = var.subnetwork_self_link_sysnet
  zone                    = var.zone
}

module "slurm_controller" {
  source                        = "./modules/embedded/community/modules/scheduler/schedmd-slurm-gcp-v6-controller"
  controller_startup_script     = module.controller_startup.startup_script
  deployment_name               = var.deployment_name
  disk_size_gb                  = var.disk_size_gb
  enable_cleanup_compute        = true
  enable_controller_public_ips  = var.enable_controller_public_ips
  enable_external_prolog_epilog = true
  instance_image                = var.instance_image
  labels                        = var.labels
  login_nodes                   = flatten([module.slurm_login.login_nodes])
  login_startup_script          = "#!/bin/bash\n# reset enroot to defaults of files under /home and running under /run\n# allows basic enroot testing with reduced I/O performance\nrm -f /etc/enroot/enroot.conf\n"
  machine_type                  = "c2-standard-8"
  network_storage               = flatten([module.data-bucket.network_storage, flatten([module.homefs.network_storage])])
  nodeset                       = flatten([module.debug_partition.nodeset, flatten([module.a3mega_partition.nodeset])])
  nodeset_dyn                   = flatten([module.debug_partition.nodeset_dyn, flatten([module.a3mega_partition.nodeset_dyn])])
  nodeset_tpu                   = flatten([module.debug_partition.nodeset_tpu, flatten([module.a3mega_partition.nodeset_tpu])])
  partitions                    = flatten([module.debug_partition.partitions, flatten([module.a3mega_partition.partitions])])
  project_id                    = var.project_id
  prolog_scripts = [{
    content  = "#!/bin/bash\nhostname | tee /etc/hostname\n"
    filename = "set_hostname_for_enroot.sh"
  }]
  region               = var.region
  slurm_cluster_name   = var.slurm_cluster_name
  slurm_conf_tpl       = "modules/embedded/community/modules/scheduler/schedmd-slurm-gcp-v6-controller/etc/long-prolog-slurm.conf.tpl"
  subnetwork_self_link = var.subnetwork_self_link_sysnet
  zone                 = var.zone
}
