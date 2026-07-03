use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct GitHubStartQuery {
    #[serde(default)]
    pub return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GitHubCallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}
