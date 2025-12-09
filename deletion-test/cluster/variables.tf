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

variable "a3mega_cluster_size" {
  description = "Toolkit deployment variable: a3mega_cluster_size"
  type        = number
}

variable "a3mega_dws_flex_enabled" {
  description = "Toolkit deployment variable: a3mega_dws_flex_enabled"
  type        = bool
}

variable "a3mega_enable_spot_vm" {
  description = "Toolkit deployment variable: a3mega_enable_spot_vm"
  type        = bool
}

variable "a3mega_partition_name" {
  description = "Toolkit deployment variable: a3mega_partition_name"
  type        = string
}

variable "a3mega_reservation_name" {
  description = "Toolkit deployment variable: a3mega_reservation_name"
  type        = string
}

variable "deployment_name" {
  description = "Toolkit deployment variable: deployment_name"
  type        = string
}

variable "disk_size_gb" {
  description = "Toolkit deployment variable: disk_size_gb"
  type        = number
}

variable "enable_controller_public_ips" {
  description = "Toolkit deployment variable: enable_controller_public_ips"
  type        = bool
}

variable "enable_login_public_ips" {
  description = "Toolkit deployment variable: enable_login_public_ips"
  type        = bool
}

variable "enable_nvidia_dcgm" {
  description = "Toolkit deployment variable: enable_nvidia_dcgm"
  type        = bool
}

variable "enable_nvidia_persistenced" {
  description = "Toolkit deployment variable: enable_nvidia_persistenced"
  type        = bool
}

variable "enable_ops_agent" {
  description = "Toolkit deployment variable: enable_ops_agent"
  type        = bool
}

variable "instance_image" {
  description = "Toolkit deployment variable: instance_image"
  type        = any
}

variable "labels" {
  description = "Toolkit deployment variable: labels"
  type        = any
}

variable "localssd_mountpoint" {
  description = "Toolkit deployment variable: localssd_mountpoint"
  type        = string
}

variable "network_id_sysnet" {
  description = "Automatically generated input from previous groups (gcluster import-inputs --help)"
  type        = any
}

variable "project_id" {
  description = "Toolkit deployment variable: project_id"
  type        = string
}

variable "region" {
  description = "Toolkit deployment variable: region"
  type        = string
}

variable "slurm_cluster_name" {
  description = "Toolkit deployment variable: slurm_cluster_name"
  type        = string
}

variable "subnetwork_self_link_sysnet" {
  description = "Automatically generated input from previous groups (gcluster import-inputs --help)"
  type        = any
}

variable "zone" {
  description = "Toolkit deployment variable: zone"
  type        = string
}
