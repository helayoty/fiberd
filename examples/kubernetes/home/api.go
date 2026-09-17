package home

import "github.com/helayoty/fiberd/examples/kubernetes/kube"

// The objects the home reads, cut down to the fields it uses.

type pod struct {
	Metadata kube.ObjectMeta `json:"metadata"`
	Spec     struct {
		NodeName           string `json:"nodeName"`
		ServiceAccountName string `json:"serviceAccountName"`
		ResourceClaims     []struct {
			Name                      string `json:"name"`
			ResourceClaimName         string `json:"resourceClaimName,omitempty"`
			ResourceClaimTemplateName string `json:"resourceClaimTemplateName,omitempty"`
		} `json:"resourceClaims,omitempty"`
	} `json:"spec"`
	Status struct {
		PodIP  string `json:"podIP"`
		PodIPs []struct {
			IP string `json:"ip"`
		} `json:"podIPs"`
		ResourceClaimStatuses []struct {
			Name              string `json:"name"`
			ResourceClaimName string `json:"resourceClaimName"`
		} `json:"resourceClaimStatuses,omitempty"`
		Conditions []kube.Condition `json:"conditions,omitempty"`
	} `json:"status"`
}

type namespace struct {
	Metadata kube.ObjectMeta `json:"metadata"`
	Status   struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

type resourceClaim struct {
	Metadata kube.ObjectMeta `json:"metadata"`
}
