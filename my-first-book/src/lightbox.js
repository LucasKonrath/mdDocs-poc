// Simple lightbox for images
document.addEventListener('DOMContentLoaded', function() {
    // Create lightbox overlay
    const overlay = document.createElement('div');
    overlay.id = 'image-overlay';
    overlay.style.cssText = `
        display: none;
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0, 0, 0, 0.9);
        z-index: 10000;
        cursor: zoom-out;
        justify-content: center;
        align-items: center;
    `;
    
    const overlayImg = document.createElement('img');
    overlayImg.style.cssText = `
        max-width: 95%;
        max-height: 95%;
        object-fit: contain;
        box-shadow: 0 0 30px rgba(0, 0, 0, 0.5);
    `;
    
    overlay.appendChild(overlayImg);
    document.body.appendChild(overlay);
    
    // Add click handler to close
    overlay.addEventListener('click', function() {
        overlay.style.display = 'none';
    });
    
    // Make all content images clickable
    const contentImages = document.querySelectorAll('.content img');
    contentImages.forEach(function(img) {
        img.style.cursor = 'zoom-in';
        img.addEventListener('click', function(e) {
            e.preventDefault();
            overlayImg.src = this.src;
            overlay.style.display = 'flex';
        });
    });
    
    // Close on ESC key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && overlay.style.display === 'flex') {
            overlay.style.display = 'none';
        }
    });
});
