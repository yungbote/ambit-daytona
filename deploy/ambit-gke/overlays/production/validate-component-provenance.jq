# Copyright 2026 Ambit
# SPDX-License-Identifier: AGPL-3.0
# Bind both metadata locations to the component in the actual Pod container.
def annotations_match($annotations; $binding):
  $annotations["ambit.sh/source-url"] == $source and
  $annotations["ambit.sh/source-revision"] == $binding[$phase];
def unrelated_source_claim:
  any([.metadata.annotations, .spec.template.metadata.annotations][];
    .["ambit.sh/source-url"] == $source or
    (.["ambit.sh/source-revision"] != null and .["ambit.sh/source-url"] == null));
def without_revision_annotations:
  del(.metadata.annotations["ambit.sh/source-revision"],
      .spec.template.metadata.annotations["ambit.sh/source-revision"]);

$bindings[0] as $by_image |
map(
  [.spec.template.spec.containers[]?.image | select($by_image[.] != null)] as $images |
  if ($images | length) == 0 then
    if unrelated_source_claim or
       ([.. | strings | select(contains("SOURCE_REVISION_REQUIRED"))] | length) > 0
    then error("Daytona component provenance appears on an unrelated resource")
    else null end
  elif ($images | length) != 1 then
    error("Daytona workload must have one component container")
  else
    $by_image[$images[0]] as $binding |
    (if .kind == "Job" and $binding.component == "api" then "migration" else $binding.component end) as $role |
    (if $role == "migration" then "migrate" else $role end) as $container_name |
    [.spec.template.spec.containers[]? | select(.name == $container_name)] as $main |
    if ($main | length) != 1 or $main[0].image != $images[0] or .metadata.labels["app.kubernetes.io/name"] != "daytona" or
       .metadata.labels["app.kubernetes.io/component"] != $role or
       .spec.template.metadata.labels["app.kubernetes.io/component"] != $role or
       (if $binding.component == "runner" then .kind != "StatefulSet"
        elif $binding.component == "api" then (.kind != "Deployment" and .kind != "Job")
        else .kind != "Deployment" end) or
       (annotations_match(.metadata.annotations; $binding) | not) or
       (annotations_match(.spec.template.metadata.annotations; $binding) | not) or
       ([.spec.template.spec.initContainers[]?.image | select($by_image[.] != null and . != $images[0])] | length) > 0 or
       ([without_revision_annotations | .. | strings | select(contains("SOURCE_REVISION_REQUIRED"))] | length) > 0
    then error("Daytona workload image, role and source annotations differ")
    else {image:$images[0], component:$binding.component, kind:.kind} end
  end
) | map(select(. != null)) as $workloads |
all($by_image | to_entries[];
  .key as $image | .value.component as $component |
  [$workloads[] | select(.image == $image) | .kind] | sort |
  . == (if $component == "api" then ["Deployment", "Job"]
        elif $component == "runner" then ["StatefulSet"] else ["Deployment"] end)
) or error("Daytona workload roster or API/migration image agreement differs")
