//! Moniteurs de détection. Chacun tourne dans sa propre tâche tokio et
//! envoie ses alertes au dispatcher via un canal `mpsc`.

pub mod audit;
pub mod fs;
pub mod net;
pub mod process;
