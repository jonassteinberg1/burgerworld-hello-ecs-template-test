rule "terraform_deprecated_interpolation" {
  enabled = true
}

rule "terraform_documented_outputs" {
    enabled = true
}

rule "terraform_documented_variables" {
    enabled = true
}

rule "terraform_typed_variables" {
    enabled = true
}

rule "terraform_required_version" {
    enabled = true
}

rule "terraform_required_providers" {
  enabled = true
}

rule "terraform_unused_required_providers" {
  enabled = true
}

# would be nice
#rule "aws_resource_missing_tags" {
#  enabled = true
#  tags = [
#    "Project",
#    "Environment",
#    "Version",
#  ]
#}

rule "terraform_naming_convention" {
  # defaults to snake_case
  enabled = true
}
