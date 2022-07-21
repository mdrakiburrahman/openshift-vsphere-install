# ============================
# Cleanup leftover MIAA PVCs
# ============================
# Get all in use PVCs
declare -a used_pvc_array
used_pvc_array=($(kubectl get po -o json -n azure-arc-data | jq -j '.items[] | "\(.metadata.namespace), \(.metadata.name), \(.spec.volumes[].persistentVolumeClaim.claimName)\n"' | grep -v null | tail -n +2 | awk '{print $3}'))

# Get all PVCs
declare -a all_pvc_array
all_pvc_array=($(kubectl get pvc -o json -n azure-arc-data | jq -j '.items[] | "\(.metadata.name) \n"'| grep -v null | tail -n +2 | awk '{print $1}'))

# Loop over all_pvc_array and print those that are not in used_pvc_array
for i in ${!all_pvc_array[@]}; do
  pvc=${all_pvc_array[$i]}
  if ! [[ "${used_pvc_array[@]}" =~ "${pvc}" ]]; then
    echo "Cleaning up MIAA PVC ${pvc} in Kubernetes..."
    kubectl delete pvc $pvc -n azure-arc-data
  fi
done