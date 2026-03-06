try {
    require('pdfkit');
    console.log('pdfkit OK');
} catch (e) {
    console.error('pdfkit MISSING:', e.message);
}
try {
    require('google-auth-library');
    console.log('google-auth-library OK');
} catch (e) {
    console.error('google-auth-library MISSING:', e.message);
}
