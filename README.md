# uberclick
Uber ordering for the browser with one click

## Development
The server can be run in development by
```shell
$ cd cmd/uberclick && UBERCLICK_REDIS_SERVER_URL=redis://localhost:6379 go run main.go --http1=true
```

and then visit
http://localhost:9899

### Environment variables
Variable|Default|Required|Description
---|---|---|---
UBERCLICK_REDIS_SERVER_URL||True|The URL of the Redis server URL. Sample set: `UBERCLICK_REDIS_SERVER_URL=redis://localhost:6379`
