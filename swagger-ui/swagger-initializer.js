window.onload = function() {
  window.ui = SwaggerUIBundle({
    url: "https://se-project-7kfh.onrender.com/php/doc.php",
    dom_id: '#swagger-ui',
    deepLinking: true,
    presets: [
      SwaggerUIBundle.presets.apis,
      SwaggerUIStandalonePreset
    ],
    plugins: [
      SwaggerUIBundle.plugins.DownloadUrl
    ],
    layout: "StandaloneLayout",
    // Critical additions below
    requestInterceptor: function(req) {
      // Force all API try-out requests to use your Render domain
      if (req.url.startsWith('/')) {
        req.url = 'https://se-project-7kfh.onrender.com/php' + req.url;
      }
      return req;
    },
    responseInterceptor: function(res) {
      // Handle potential CORS issues
      if (!res.ok) {
        console.error('API request failed:', res);
      }
      return res;
    }
  });
};