locals {
  truncated_executor_len = min(length(var.name), 28 - length("executor-"))
  executor_name          = "executor-${substr(var.name, 0, local.truncated_executor_len)}"
  truncated_builder_len  = min(length(var.name), 28 - length("builder-"))
  builder_name           = "builder-${substr(var.name, 0, local.truncated_builder_len)}"
  truncated_invoker_len  = min(length(var.name), 28 - length("invoker-"))
  invoker_name           = "invoker-${substr(var.name, 0, local.truncated_invoker_len)}"
  builder_source_buckets = [
    google_storage_bucket.binaries.name,
    "gcf-v2-sources-${local.project_number}-${local.region}",
    "gcf-v2-uploads-${local.project_number}-${local.region}",
  ]
  builder_source_bucket_condition = join(" || ", [
    for bucket in local.builder_source_buckets :
    "resource.name.startsWith(\"projects/_/buckets/${bucket}\")"
  ])
}

resource "google_service_account" "executor" {
  account_id   = local.executor_name
  display_name = "Executor for vault admin ${var.name}"
}

resource "google_project_iam_member" "executor_artifacts" {
  project = local.project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.executor.email}"
}

resource "google_secret_manager_secret_iam_member" "executor" {
  project   = local.project_id
  secret_id = var.token_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.executor.email}"
}

resource "google_service_account" "builder" {
  account_id   = local.builder_name
  display_name = "Builder for vault admin ${var.name}"
}

resource "google_service_account_iam_member" "builder_user" {
  service_account_id = google_service_account.builder.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${local.project_number}@cloudbuild.gserviceaccount.com"
}

resource "google_project_iam_member" "builder_build" {
  project = local.project_id
  role    = "roles/cloudbuild.builds.builder"
  member  = "serviceAccount:${google_service_account.builder.email}"
}

resource "google_project_iam_member" "builder_artifacts" {
  project = local.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${google_service_account.builder.email}"
}

# Gen2 copies the zip into gcf-v2 buckets that do not exist until the first deploy.
resource "google_project_iam_member" "builder_source" {
  project = local.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.builder.email}"

  condition {
    title      = "source-buckets-only"
    expression = local.builder_source_bucket_condition
  }
}

resource "google_service_account" "invoker" {
  account_id   = local.invoker_name
  display_name = "Invoker for vault admin ${var.name}"
}

resource "google_cloud_run_service_iam_member" "invoker" {
  project  = local.project_id
  location = google_cloudfunctions2_function.this.location
  service  = basename(google_cloudfunctions2_function.this.service_config[0].service)
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.invoker.email}"
}

resource "google_service_account_iam_binding" "invoker_token" {
  count              = length(var.invoker_impersonators) == 0 ? 0 : 1
  service_account_id = google_service_account.invoker.id
  role               = "roles/iam.serviceAccountTokenCreator"
  members            = [for email in var.invoker_impersonators : "serviceAccount:${email}"]
}

resource "google_service_account_iam_binding" "invoker_idtoken" {
  count              = length(var.invoker_impersonators) == 0 ? 0 : 1
  service_account_id = google_service_account.invoker.id
  role               = "roles/iam.serviceAccountOpenIdTokenCreator"
  members            = [for email in var.invoker_impersonators : "serviceAccount:${email}"]
}

resource "google_cloudfunctions2_function" "this" {
  depends_on = [
    google_project_service.run,
    google_project_service.cloudbuild,
    google_project_service.function,
    google_project_service.artifact_registry,
  ]

  name     = var.name
  location = local.region
  labels   = var.labels

  build_config {
    runtime         = "go125"
    entry_point     = "vault-admin"
    service_account = google_service_account.builder.id

    environment_variables = {
      SOURCE_HASH = filebase64sha256(local.package_filename)
    }

    source {
      storage_source {
        bucket = google_storage_bucket.binaries.name
        object = google_storage_bucket_object.binary.name
      }
    }
  }

  service_config {
    service_account_email          = google_service_account.executor.email
    timeout_seconds                = 20
    available_memory               = "256Mi"
    max_instance_count             = 3
    all_traffic_on_latest_revision = true
    vpc_connector                  = var.vpc_access_connector_name
    vpc_connector_egress_settings  = "ALL_TRAFFIC"
    ingress_settings               = "ALLOW_ALL"

    secret_environment_variables {
      key        = "VAULT_TOKEN"
      project_id = local.project_id
      secret     = var.token_secret_id
      version    = "latest"
    }

    environment_variables = {
      VAULT_ADDR = var.vault_addr
    }
  }
}
