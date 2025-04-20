#include <leptonica/allheaders.h>
#include <tesseract/baseapi.h>

#include <libgen.h> // for dirname
#include <cstdio>   // for printf
#include <cstdlib>  // for std::getenv, std::setenv
#include <string>   // for std::string

static tesseract::TessBaseAPI *api = nullptr;


int main (int argc, char **argv) {
    if (argc != 2) {
        //  fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
          return 1;
      }
  
      // Read input file
      const char *input_file = argv[1];
      Pix *image = pixRead(input_file);
      if (!image) {
        //  fprintf(stderr, "Failed to read input image: %s\n", input_file);
          return 1;
      }

    api = new tesseract::TessBaseAPI();

    if (api->Init(nullptr, "eng")) {
        fprintf(stderr, "Failed to initialize Tesseract\n");
        exit(1);
    }


    api->SetImage(image);

    char *outText = api->GetUTF8Text();

    pixDestroy(&image);
    delete[] outText;

    return 0;
}