job "example-http-service" {
  datacenters = ["dc1"]
  type = "service"
  
  group "example-http" {
    count = 1

    network {
      port "http" {
        to = 80
      }
    }

    service {
      name = "example-http-service"
      port = "http"

      tags = [
        "traefik.enable=true",
        "traefik.http.routers.example-http-service.entryPoints=http",
        "traefik.http.routers.example-http-service.rule=Path(`/example-http-service`)"
      ]

      check {
        type     = "http"
        path     = "/"
        interval = "30s"
        timeout  = "2s"
      }
    }

    task "http-service" {
      driver = "docker"

      config {
        image = "nginx:latest"
        ports = ["http"]
      }

      resources {
        cpu    = 500
        memory = 256
      }

      env = {
        "EXAMPLE_VAR" = "example_value"
      }
    }
  }
}
