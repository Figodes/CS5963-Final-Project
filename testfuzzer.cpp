#include <~/fuzzing/tesseract/baseapi.h>
#include <~/fuzzing/leptonica/allheaders.h>
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

    int* orientation = 0;
    float* orientation_conf = 0;
    const char** script = 0;
    float* script_conf = 0;
    api->DetectOrientationScript(orientation, orientation_conf, script, script_conf);
    api->MeanTextConf();
    api->AllWordConfidences();

    char *text = api->GetUTF8Text();
    if (text) {
        printf("OCR Output:\n%s\n", text);
        delete[] text;
    }

    // Cleanup
    api->End();
    api->ClearPersistentCache();
    delete api;

    pixDestroy(&image);

    return 0;
}
