# denyip Traefik Plugin

Blocks requests from configured IPs or CIDR ranges.

## Config Example

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: denyip
spec:
  plugin:
    denyip:
      IPDenyList:
        - "1.2.3.4"
        - "10.0.0.0/8"
