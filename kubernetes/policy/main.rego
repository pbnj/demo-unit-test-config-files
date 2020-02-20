package main

name = input.metadata.name

deny[msg] {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot

	msg = sprintf("Containers must run as non root in Deployment %s. See: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/", [name])
}
