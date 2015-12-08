listen = ":8053"
log-level = "info"

recursors = ["8.8.8.8:53", "8.8.4.4:53"]

forwarder "consul"{
    pattern = "consul."
    address = "172.20.16.125:8600"
    limit = 1
}
