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
    prefix = "a3mega-slurm/deletion-test/primary"
  }
}

module "sysnet" {
  source                = "./modules/embedded/modules/network/vpc"
  deployment_name       = var.deployment_name
  labels                = var.labels
  mtu                   = 8244
  network_address_range = var.sys_net_range
  network_name          = var.network_name_system
  project_id            = var.project_id
  region                = var.region
  subnetworks = [{
    description           = "primary subnetwork in gsc-sys-net"
    new_bits              = 4
    subnet_name           = var.subnetwork_name_system
    subnet_private_access = true
    subnet_region         = var.region
  }]
}
