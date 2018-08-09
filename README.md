# elastic-notes

Install the Elastic Stack on Red Hat 7

PREREQUISITES
==============

1. RPM/Installation packages/artifacts required.

- jdk-8u171-linux-x64.rpm (min version for version 6.x is currently jdk-8u131)
- elasticsearch.6.3.1.rpm
- kibana.6.3.4-x86_64.rpm  
- nginx.1.14.0.rpm
- logstash.6.3.1.rpm  
- beats rpms
- configuration files
- license key
- SSL certificates

2. Node configuration 
- VM's run on VMWare ESXi v6.5
- Use the following information to create the virtual machine.  
- Use the fully qualified domain name (FQDN) as the system hostname.

System       Node Type       Disk      Memory     Heap     CPU
--------     -----------     -----     ------     ----     ----
Elastic1     Data/Master     256GB      32GB      16GB      4
Elastic2     Data/Master     256GB      32GB      16GB      4
Elastic3     Data/Master     256GB      32GB      16GB      4
Kibana       www/elastic4    256GB      32GB       4GB      6
Logstash1         -          256GB      32GB       -        4

File systesm layout:

Directory          Size                           Type
--------------     --------------------------     ----
/                   ~64 GiB (remaining space)     ext4
/boot               250 MiB                       ext4
swap               8192 MiB                       ext4
/tmp                 10 GiB                       ext4
/home                15 GiB                       ext4
/var                  5 GiB                       ext4
/var/log              5 GiB                       ext4
/var/log/audit       10 GiB                       ext4
/var/data *         100 GiB                       ext4
/var/data **         10 TB (RAID0+1)              ext4

 * internal disk for Kibana/Logstash1
** external from NAS for Elastic nodes; dedicated for each
  
3. Stage the Elastic installation artifacts.

- Installation RPM files, configuration files, and certifications should be pushed to each node.  Place the artifacts in the /var/tmp/ELK folder (create if necessary).  Transfer the files as the "admin" user.

- Obtain SSL certificates for each node:
  -- Ensure the certificates support both server and client authentication and are in the pem format.
  -- Ensure the certificates’ Netscape Certificate type supports server and client authentication.
  -- Ensure the certificates support the DNS application name, hostname, and IP Address for each node.
  -- Generate an unencrypted private key for the kibana server certificate.

      root# openssl rsa –in {fqdn}.key.pem –out {fqdn}.key.2.pem


INSTALL JAVA  
==============  
 
The Elastic stack deployment requires Java. It supports both OpenJDK and Oracle Java.  We will install Oracle JDK 1.8. We will
install Java 8 (jdk-8u181-linux-x64.rpm) from the official Oracle rpm package.

  root# rpm -ivh jdk-8u181-linux-x64.rpm
  root# java -version
  
  java version "1.8.0_181"
  Java(TM) SE Runtime Environment (build 1.8.0_181-b11)
  Java HotSpot(TM) 64-Bit Server VM (build 25.181-b11, mixed mode)


INSTALL AND CONFIGURE ELASTICSEARCH
=====================================

1.  We will use rpm package for this installation.  Packages should have been deployed to the /var/tmp/ELK folder on each node.

    root# rpm -ivh elasticsearch-6.3.2.rpm

2.  Complete the basic elasticsearch configuration (/etc/elasticsearch/elasticsearch.yml).  The basic configuration does not include SSL
or Active Directory/LDAP authentication. A copy of the configuration is in the deployment directory (elasticsearch.yml_nossl).  Contents of the file should read similar to the following:

cluster.name: Production
node:
  name: ${HOSTNAME}
  master: true
  data:   true
  ingest: false
  ml:     true
  attr:
    box_type: hot
  
path:
  data: /var/data/lib/elasticsearch
  logs: /var/data/log/elasticsearch
  
bootstrap.memory_lock: true

network.host: ${HOSTNAME}
http.port: 9200
transport.tcp.port: 9300-9400

discovery.zen:
  ping.unicast.hosts [ "elastic1", "elastic2", "elastic3" ]
  minimumn_master_nodes: 2

search.remote.connect: false


3.  Configure memory locking.

- Create override.conf (/etc/systemd/system/elasticsearch.service.d).  The folder will NOT exist initially; it is
created as follows.  Once the data entry is complete, press “Ctrl-X”, “Y”, then press the <Enter> key.
  
  root# systemctl edit elasticsearch.service

  [Service]
  LimitMEMLOCK=infinity

- Add the following to limits.conf (/etc/security) before the line that reads “# End of file”.

  elasticsearch     soft    nofile  65536
  elasticsearch     hard    nofile  65536
  elasticsearch     soft    memlock unlimited
  elasticsearch     hard    memlock unlimited
  root              -       memlock unlimited

- Uncomment/Update the following lines in the elasticsearch (/etc/sysconfig) service configuration file.

  ES_HOME=/usr/share/elasticsearch
  JAVA_HOME=/usr/java/latest
  ES_PATH_CONF=/etc/elasticsearch
  PID_DIR=/var/run/elasticsearch
  MAX_OPEN_FILES=65536
  MAX_LOCKED_MEMORY=unlimited

- Reload the services and enable elasticsearch.

  root# systemctl daemon-reload
  root# systemctl enable elasticsearch
  root# systemctl start elasticsearch

- Verify the elasticsearch configuration.
  
  root# systemctl status elasticsearch
  root# curl http://`hostname`:9200/_nodes?pretty

  ## Expected output
  {
    "name" : "Coordinator",
    "cluster_name"  : "Production",
    "cluster_uuid"  : "AT69_T_DTp-1qgIJlatQqA",
    "version"  : {
      "number" : "6.3.1",
      "build_flavor" : "default",
      "build_type" : "rpm",
      "build_hash" : "eb82d0",
      "build_date" : "2018-04-12T20:37:28.497551Z",
      "build_snapshot" : false,
      "lucene_version" : "7.3.1",
      "minimum_wire_compatibility_version" : "5.6.0",
      "minimum_index_compatibility_version" : "5.0.0"
    },
    "tagline"  : "You Know, for Search"
  }

- Install the license key.

  root# cd /var/tmp/ELK
  root# curl -XPUT -u elastic 'https://{node}:9200/_xpack/license' \
             --insecure \
             -H "Content-Type:application/json" \
             -d  @`pwd`/usaf-robins-production-….json
  Enter host password for user 'elastic': ****************
  {“acknowledged”:true, “license_status”:”valid”}

- Configure X-Pack.

Copy the CA certificate and private key from the deployment directory to the /etc/pki/root directory; ensure permission are root:root 0444.

Copy the nodes certificate and private key from the deployment directory to the /etc/elasticsearch/certs directory; ensure permission are root:elasticsearch 0444.

Update the elasticsearch configuration file (/etc/elasticsearch/elasticsearch.yml) with the following information; update hostname and domain names as necessary for the enclave.  The full elasticsearch configuration file is found in the deployment directory (elasticsearch.yml_ssl_auth).

# ---------------------------------- X-Pack ----------------------
xpack:
  ml.enabled: true
  monitoring.enabled: true
  security:
    enabled: true
    audit.enabled: true
    authc.realms:
      native1:
        type: native1
        order: 0
      active_directory:
        type: active_directory
        order: 1
        domain_name: {domainname}
        url: ldap://{domainname}:389
    transport.ssl: 
      enabled: true     
      verification_mode: certificate    
      key: certs/elastic1.key.pem
      certificate: certs/elastic1.cert.pem
      certificate_authorities: ["/etc/pki/root/ca.cert.pem"]  
    http.ssl:    
      enabled: true
      key: certs/elastic1.key.pem    
      certificate: certs/elastic1.cert.pem
      certificate_authorities: ["/etc/pki/root/ca.cert.pem" ]

- Restart elasticsearch and check the status (after approximately 30 seconds).

  root# systemctl restart elasticsearch
  root# systemctl status elasticsearch

- Verify the Elasticsearch node’s configuration using SSL.

  root# curl –u {username} https://`hostname`:9200/_nodes?pretty \
        --cacert /etc/pki/root/ca.cert.pem
  Enter host password for user {username}: ********
  
  ## Expected Output
  {
    "name" : "Coordinator",
    "cluster_name" : "AF-DCGS-ESD",
    "cluster_uuid" : "AT69_T_DTp-1qgIJlatQqA",
    "version : {
      "number" : "6.3.1",
      "build_flavor" : "default",
      "build_type" : "rpm",
      "build_hash" : "eb82d0",
      "build_date" : "2018-04-12T20:37:28.497551Z",
      "build_snapshot" : false,
      "lucene_version" : "7.3.1",
      "minimum_wire_compatibility_version" : "5.6.0",
      "minimum_index_compatibility_version" : "5.0.0"
    },
    "tagline" : "You Know, for Search"
  }

- After all nodes are installed (elastic1-3 and kibana node), verify the Elasticsearch Cluster configuration.

  root# curl –u {username} https://`hostname`:9200/_nodes/process?pretty \
        --insecure

## Expected Output
{
  "_nodes" : {
    "total" : 4,
    "successful" : 4,
    "failed" : 0
  },
  "cluster_name" : "Production",
  "nodes" : {
    ... { attributes for each node follows }
  }
}
