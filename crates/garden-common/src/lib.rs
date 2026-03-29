pub mod ipc {
    tonic::include_proto!("garden.agent.v1");
}

pub mod daemon {
    tonic::include_proto!("garden.daemon.v1");
}
