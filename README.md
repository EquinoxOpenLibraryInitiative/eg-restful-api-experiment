# Evergreen RESTful API Experiment

This is a `Mojolicious::Lite` application that extends an
experiment / proof-of-concept for creating a RESTful
API for Evergreen that's based on

- OpenAPI 3.0.0
- `Mojolicious` and `Mojolicious::Plugin::OpenAPI`

To install and run:

```
cpan Mojolicious::Plugin::OpenAPI
./eg-api.pl daemon -m production -l http://localhost:8080
```

You will also need to add an nginx configuration block
within the server section that listens on port 443 to
provide HTTPS support / redirection:

```
 location /openapi3 {
     proxy_pass http://localhost:8080;
     proxy_set_header Host $host;
     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
     proxy_set_header X-Forwarded-Proto $scheme;
     proxy_read_timeout 300s;
 }
```

`eg-api.pl` assumes that it is running on an Evergreen system
whose core config is located at `/openils/conf/opensrf_core.xml`.

