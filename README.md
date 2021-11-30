# Evergreen RESTful API Experiment

This is a `Mojolicious::Lite` application that is an
experiment / proof-of-concept for creating a RESTful
API for Evergreen that's based on

- OpenAPI 3.0.0
- `Mojolicious` and `Mojolicious::Plugin::OpenAPI`

To install and run:

```
cpan Mojolicious::Plugin::OpenAPI
./eg-api.pl daemon -m production -l http://*:8080
```

`eg-api.pl` assumes that it is running on an Evergreen system
whose core config is located at `/openils/conf/opensrf_core.xml`
