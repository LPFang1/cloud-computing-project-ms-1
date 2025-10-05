// redoc-init.js - initialize ReDoc and surface errors to console
(function() {
  try {
    const specUrl = window.location.origin + '/openapi.yaml';
    if (!window.Redoc) {
      console.error('ReDoc library not loaded');
      return;
    }

    // Initialize ReDoc and log if any error occurs
    Redoc.init(specUrl, { scrollYOffset: 50 }, document.getElementById('redoc'))
      .then(() => console.log('ReDoc initialized with', specUrl))
      .catch((err) => {
        console.error('ReDoc init failed:', err);
      });
  } catch (err) {
    console.error('Unexpected error initializing ReDoc:', err);
  }
})();
