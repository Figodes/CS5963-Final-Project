#include <tesseract/baseapi.h>
#include <leptonica/allheaders.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

__AFL_FUZZ_INIT(); 

// Global Tesseract instance to avoid reinitialization
static tesseract::TessBaseAPI *api = nullptr;

int main(int argc, char **argv) {
    // init once
    api = new tesseract::TessBaseAPI();
    if (api->Init(nullptr, "eng")) {
        fprintf(stderr, "Failed to initialize Tesseract\n");
        exit(1);
    }

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();  // Start AFL++ manual mode
#endif

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // Buffer for test cases

    while (__AFL_LOOP(10000)) {  // Persistent mode loop
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < 8) continue;  // Skip very small inputs

        Pix *image = pixReadMem(buf, len);
        if (!image) continue;  // Skip invalid images

        // Process the image with Tesseract
        Pixa** pixa;
        int** blockids;
        int** paraids;
        // Process the image
        api->SetImage(image);
        api->SetRectangle(0, 0, image->w, image->h); // Set the whole image as the rectangle
        api->GetRegions(pixa);
        api->GetTextlines(true, 0, pixa, blockids, paraids);
        api->GetStrips(pixa, blockids);
        api->GetWords(pixa);
        api->GetConnectedComponents(pixa);
        api->AnalyseLayout();
    
        api->Recognize(NULL); // Recognize the image
    
        // TessResultRenderer *renderer = TessTextRendererCreate("output");
        // api->ProcessPage(image, 0, input_file, NULL, 0, renderer); 
        api->GetIterator(); // Get the iterator for the recognized text
        char *text = api->GetUTF8Text();
        if (text) delete[] text;

        // Cleanup
        pixDestroy(&image);
    }

    // Cleanup Tesseract after fuzzing is complete
    api->End();
    delete api;

    return 0;
}
