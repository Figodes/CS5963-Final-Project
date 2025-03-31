// duncan attempting a fuzzer for afl by reading in an image (unlike the existing one)
#include <tesseract/baseapi.h>
#include <leptonica/allheaders.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    // Read input file
    const char *input_file = argv[1];
    Pix *image = pixRead(input_file);
    if (!image) {
        fprintf(stderr, "Failed to read input image: %s\n", input_file);
        return 1;
    }

    // Initialize Tesseract
    tesseract::TessBaseAPI *api = new tesseract::TessBaseAPI();
    if (api->Init(NULL, "eng")) { 
        fprintf(stderr, "Failed to initialize Tesseract\n");
        pixDestroy(&image);
        return 1;
    }

    // Process the image
    api->SetImage(image);
    char *text = api->GetUTF8Text();
    if (text) {
        printf("OCR Output:\n%s\n", text);
        delete[] text;
    }

    // Cleanup
    api->End();
    delete api;
    pixDestroy(&image);

    return 0;
}
