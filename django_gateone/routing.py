from channels import route_class, route
from applications.server import ApplicationWebSocket


# The channel routing defines what channels get handled by what consumers,
# including optional matching on message attributes. In this example, we route
# all WebSocket connections to the class-based BindingConsumer (the consumer
# class itself specifies what channels it wants to consume)
channel_routing = [
    route_class(ApplicationWebSocket,path = r'^/ws/$'),
]