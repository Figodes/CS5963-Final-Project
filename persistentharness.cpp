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
    // Init once
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
        api->SetImage(image);
        api->SetRectangle(0, 0, pixGetWidth(image), pixGetHeight(image)); 

        // init pointers so there isn't a segfault
        Pixa** regions = NULL;
        Pixa** textlines = NULL;
        Pixa** words = NULL;
        Pixa** components = NULL;
        int** blockids = NULL;
        int** paraids = NULL;
        // Call verious functions
        api->GetRegions(regions);
        api->GetTextlines(true, 0, textlines, blockids, paraids);
        api->GetStrips(regions, blockids);
        api->GetWords(words);
        api->GetConnectedComponents(regions);
        // Safely call layout analysis functions
        api->AnalyseLayout();
        
        // Perform OCR
        api->Recognize(NULL);
        
        // Get orientation information
        int orientation = 0;
        float orientation_conf = 0;
        const char* script_name = nullptr;
        float script_conf = 0;
        api->DetectOrientationScript(&orientation, &orientation_conf, &script_name, &script_conf);
        
        // make more calls
        api->MeanTextConf();
        api->GetIterator();
        api->GetUTF8Text();
        api->AllWordConfidences();
        

        // Cleanup for this iteration
        pixDestroy(&image);
        
        // Reset the API for the next iteration
        api->Clear();
    }

    // Cleanup Tesseract after fuzzing is complete
    api->End();
    delete api;
    
    return 0;
}
