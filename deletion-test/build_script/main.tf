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
    prefix = "a3mega-slurm/deletion-test/build_script"
  }
}

module "image_build_script" {
  source                      = "./modules/embedded/modules/scripts/startup-script"
  configure_ssh_host_patterns = ["10.0.0.*", "10.1.0.*", "10.2.0.*", "10.3.0.*", "10.4.0.*", "10.5.0.*", "10.6.0.*", "10.7.0.*", "${var.slurm_cluster_name}*"]
  deployment_name             = var.deployment_name
  docker = {
    enabled        = true
    world_writable = true
  }
  enable_gpu_network_wait_online = true
  install_ansible                = true
  labels                         = var.labels
  project_id                     = var.project_id
  region                         = var.region
  runners = [{
    content     = "---\n- name: Hold nvidia packages\n  hosts: all\n  become: true\n  vars:\n    nvidia_packages_to_hold:\n    - libnvidia-cfg1-*-server\n    - libnvidia-compute-*-server\n    - libnvidia-nscq-*\n    - nvidia-compute-utils-*-server\n    - nvidia-fabricmanager-*\n    - nvidia-utils-*-server\n    - nvidia-imex-*\n  tasks:\n  - name: Hold nvidia packages\n    ansible.builtin.command:\n      argv:\n      - apt-mark\n      - hold\n      - \"{{ item }}\"\n    loop: \"{{ nvidia_packages_to_hold }}\"\n"
    destination = "hold-nvidia-packages.yml"
    type        = "ansible-local"
    }, {
    content     = "#!/bin/bash\nset -e -o pipefail\napt-mark hold google-compute-engine\napt-mark hold google-compute-engine-oslogin\napt-mark hold google-guest-agent\napt-mark hold google-osconfig-agent\n"
    destination = "prevent_google_compute_upgrades.sh"
    type        = "shell"
    }, {
    content     = "{\n  \"reboot\": false,\n  \"install_cuda\": false,\n  \"install_ompi\": true,\n  \"install_lustre\": false,\n  \"install_managed_lustre\": false,\n  \"install_gcsfuse\": true,\n  \"monitoring_agent\": \"cloud-ops\",\n  \"use_open_drivers\": true\n}\n"
    destination = "/var/tmp/slurm_vars.json"
    type        = "data"
    }, {
    content     = "#!/bin/bash\nset -e -o pipefail\napt-get update\napt-get install -y git\nansible-galaxy role install googlecloudplatform.google_cloud_ops_agents\nansible-pull \\\n    -U https://github.com/GoogleCloudPlatform/slurm-gcp -C 6.10.6 \\\n    -i localhost, --limit localhost --connection=local \\\n    -e @/var/tmp/slurm_vars.json \\\n    ansible/playbook.yml\n"
    destination = "install_slurm.sh"
    type        = "shell"
    }, {
    content     = "---\n- name: Install updated gVNIC driver from GitHub\n  hosts: all\n  become: true\n  vars:\n    package_url: https://github.com/GoogleCloudPlatform/compute-virtual-ethernet-linux/releases/download/v1.4.3/gve-dkms_1.4.3_all.deb\n    package_filename: /tmp/{{ package_url | basename }}\n  tasks:\n  - name: Install driver dependencies\n    ansible.builtin.apt:\n      name:\n      - dkms\n  - name: Download gVNIC package\n    ansible.builtin.get_url:\n      url: \"{{ package_url }}\"\n      dest: \"{{ package_filename }}\"\n  - name: Install updated gVNIC\n    ansible.builtin.apt:\n      deb: \"{{ package_filename }}\"\n      state: present\n"
    destination = "update-gvnic.yml"
    type        = "ansible-local"
    }, {
    content     = "#!/bin/bash\nset -ex -o pipefail\nadd-nvidia-repositories -y\napt update -y\napt install -y cuda-toolkit-12-8\napt install -y nvidia-container-toolkit\napt install -y datacenter-gpu-manager-4-cuda12\napt install -y datacenter-gpu-manager-4-dev\n"
    destination = "install-cuda-toolkit.sh"
    type        = "shell"
    }, {
    content     = "* - memlock unlimited\n* - nproc unlimited\n* - stack unlimited\n* - nofile 1048576\n* - cpu unlimited\n* - rtprio unlimited\n"
    destination = "/etc/security/limits.d/99-unlimited.conf"
    type        = "data"
    }, {
    content     = "ENROOT_CONFIG_PATH     $${HOME}/.enroot\nENROOT_RUNTIME_PATH    /mnt/localssd/$${UID}/enroot/runtime\nENROOT_CACHE_PATH      /mnt/localssd/$${UID}/enroot/cache\nENROOT_DATA_PATH       /mnt/localssd/$${UID}/enroot/data\nENROOT_TEMP_PATH       /mnt/localssd/$${UID}/enroot\n"
    destination = "/etc/enroot/enroot.conf"
    type        = "data"
    }, {
    content     = "---\n- name: Install CUDA & DCGM & Configure Ops Agent\n  hosts: all\n  become: true\n  vars:\n    enable_ops_agent: ${var.enable_ops_agent}\n    enable_nvidia_dcgm: ${var.enable_nvidia_dcgm}\n  tasks:\n  - name: Create nvidia-persistenced override directory\n    ansible.builtin.file:\n      path: /etc/systemd/system/nvidia-persistenced.service.d\n      state: directory\n      owner: root\n      group: root\n      mode: 0o755\n  - name: Configure nvidia-persistenced override\n    ansible.builtin.copy:\n      dest: /etc/systemd/system/nvidia-persistenced.service.d/persistence_mode.conf\n      owner: root\n      group: root\n      mode: 0o644\n      content: |\n        [Service]\n        ExecStart=\n        ExecStart=/usr/bin/nvidia-persistenced --user nvidia-persistenced --verbose\n    notify: Reload SystemD\n  handlers:\n  - name: Reload SystemD\n    ansible.builtin.systemd:\n      daemon_reload: true\n  post_tasks:\n  - name: Enable Google Cloud Ops Agent\n    ansible.builtin.service:\n      name: google-cloud-ops-agent.service\n      state: \"{{ 'started' if enable_ops_agent else 'stopped' }}\"\n      enabled: \"{{ enable_ops_agent }}\"\n  - name: Disable NVIDIA DCGM by default (enable during boot on GPU nodes)\n    ansible.builtin.service:\n      name: nvidia-dcgm.service\n      state: stopped\n      enabled: \"{{ enable_nvidia_dcgm }}\"\n  - name: Disable nvidia-persistenced SystemD unit (enable during boot on GPU nodes)\n    ansible.builtin.service:\n      name: nvidia-persistenced.service\n      state: stopped\n      enabled: false\n"
    destination = "configure_gpu_monitoring.yml"
    type        = "ansible-local"
    }, {
    content     = "---\n- name: Install DMBABUF import helper\n  hosts: all\n  become: true\n  tasks:\n  - name: Setup apt-transport-artifact-registry repository\n    ansible.builtin.apt_repository:\n      repo: deb http://packages.cloud.google.com/apt apt-transport-artifact-registry-stable main\n      state: present\n  - name: Install driver dependencies\n    ansible.builtin.apt:\n      name:\n      - dkms\n      - apt-transport-artifact-registry\n  - name: Setup gpudirect-tcpxo apt repository\n    ansible.builtin.apt_repository:\n      repo: deb [arch=all trusted=yes ] ar+https://us-apt.pkg.dev/projects/gce-ai-infra gpudirect-tcpxo-apt main\n      state: present\n  - name: Install DMABUF import helper DKMS package\n    ansible.builtin.apt:\n      name: dmabuf-import-helper\n      state: present\n"
    destination = "install_dmabuf.yml"
    type        = "ansible-local"
    }, {
    content     = "---\n- name: Setup GPUDirect-TCPXO aperture devices\n  hosts: all\n  become: true\n  tasks:\n  - name: Mount aperture devices to /dev and make writable\n    ansible.builtin.copy:\n      dest: /etc/udev/rules.d/00-a3-megagpu.rules\n      owner: root\n      group: root\n      mode: 0o644\n      content: |\n        ACTION==\"add\", SUBSYSTEM==\"pci\", ATTR{vendor}==\"0x1ae0\", ATTR{device}==\"0x0084\", TAG+=\"systemd\", \\\n            RUN+=\"/usr/bin/mkdir --mode=0755 -p /dev/aperture_devices\", \\\n            RUN+=\"/usr/bin/systemd-mount --type=none --options=bind --collect %S/%p /dev/aperture_devices/%k\", \\\n            RUN+=\"/usr/bin/bash -c '/usr/bin/chmod 0666 /dev/aperture_devices/%k/resource*'\"\n    notify: Update initramfs\n  handlers:\n  - name: Update initramfs\n    ansible.builtin.command: /usr/sbin/update-initramfs -u -k all\n"
    destination = "aperture_devices.yml"
    type        = "ansible-local"
    }, {
    content     = "#!/bin/bash\n# IMPORTANT: This script should be run *last* in any sequence of setup steps\n# that use 'gsutil' or other gcloud commands.\n# This is because removing the Snap version of the GCloud SDK can temporarily\n# break existing 'gsutil' paths, which might disrupt other scripts still running\n# that rely on the Snap-installed version.\n\nset -e -o pipefail\n\n# Remove the previously installed Google Cloud SDK (google-cloud-cli) and\n# the LXD container manager, both of which might have been installed via Snap.\n# This step is crucial to prevent conflicts with the upcoming APT installation\n# and address potential issues with Snapd and NFS mounts in specific environments\nsnap remove google-cloud-cli lxd\n# Install key and google-cloud-cli from apt repo\nGCLOUD_APT_SOURCE=\"/etc/apt/sources.list.d/google-cloud-sdk.list\"\nif [ ! -f \"$${GCLOUD_APT_SOURCE}\" ]; then\n    # indentation matters in EOT below; do not blindly edit!\n    cat <<EOT > \"$${GCLOUD_APT_SOURCE}\"\ndeb [signed-by=/usr/share/keyrings/cloud.google.asc] https://packages.cloud.google.com/apt cloud-sdk main\nEOT\nfi\ncurl -o /usr/share/keyrings/cloud.google.asc https://packages.cloud.google.com/apt/doc/apt-key.gpg\napt-get update\napt-get install --assume-yes google-cloud-cli\n# Clean up the bash executable hash for subsequent steps using gsutil\nhash -r\n"
    destination = "remove_snap_gcloud.sh"
    type        = "shell"
  }]
}
