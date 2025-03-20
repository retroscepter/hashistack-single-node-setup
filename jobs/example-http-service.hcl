job "hello-world" {
  datacenters = ["dc1"]
  type = "service"
  
  group "hello-world" {
    count = 1

    network {
      mode = "bridge"

      port "http" {
        to = 80
      }
    }

    service {
      name = "hello-world"
      port = "http"

      tags = [
        "traefik.enable=true",
        "traefik.http.routers.hello-world.entryPoints=http",
        "traefik.http.routers.hello-world.rule=Path(`/hello-world`)"
      ]

      check {
        type     = "http"
        path     = "/"
        interval = "30s"
        timeout  = "2s"
        port     = "http"
      }
    }

    task "http-service" {
      driver = "docker"

      config {
        image = "nginx"
        ports = ["http"]
      }

      resources {
        cpu    = 500
        memory = 256
      }
    }
  }
}
