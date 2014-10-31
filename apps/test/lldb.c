#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <leveldb/c.h>

int
main(int argc, char *argv[])
{
   char *name;
   int create = 0;
   int info = 0;
   int list = 0;
   int fill = 0;
   char c;

   while ((c = getopt(argc, argv, "chilf")) != EOF) {
      switch (c) {
      case 'c':
         printf("create\n");
         create = 1;
         break;
      case 'f':
         printf("write-data\n");
         fill = 1;
         break;
      case 'i':
         printf("get-info\n");
         info = 1;
         break;
      case 'l':
         printf("list-contents\n");
         list = 1;
         break;
      case 'h':
      default:
         printf("lldb: option chil\n");
         return 1;
      }
   }
   leveldb_options_t *options;
   leveldb_t *db;
   char *errStr = NULL;

   name = argv[optind];
   if (name == NULL) {
      printf("Specify db name on cmd line.\n");
      return 1;
   }

   options = leveldb_options_create();
   if (create) {
      leveldb_options_set_create_if_missing(options, 1);
      leveldb_options_set_error_if_exists(options, 1);
   }

   printf("Opening: %s\n", name);
   db = leveldb_open(options, name, &errStr);
   if (db == NULL) {
      printf("failed to open '%s': %s\n", name, errStr);
      return 1;
   }
   if (fill) {
      leveldb_writeoptions_t *writeopts;
      leveldb_writebatch_t* wb;

      writeopts = leveldb_writeoptions_create();
      leveldb_writeoptions_set_sync(writeopts, 1);

      wb = leveldb_writebatch_create();

      leveldb_writebatch_put(wb, "bar", 3, "b", 1);
      leveldb_writebatch_put(wb, "box", 3, "c", 1);
      leveldb_writebatch_delete(wb, "bar", 3);

      leveldb_writeoptions_destroy(writeopts);
      leveldb_write(db, writeopts, wb, &errStr);
   }

   if (list) {
      leveldb_readoptions_t* readopts;
      leveldb_iterator_t *iter;

      readopts = leveldb_readoptions_create();
      leveldb_readoptions_set_verify_checksums(readopts, 1);
      leveldb_readoptions_set_fill_cache(readopts, 0);

      iter = leveldb_create_iterator(db, readopts);
      leveldb_iter_seek_to_first(iter);

      while (leveldb_iter_valid(iter)) {
         const char *key;
         const char *val;
         size_t klen;
         size_t vlen;

         key = leveldb_iter_key(iter, &klen);
         val = leveldb_iter_value(iter, &vlen);

         printf("k=%s vlen=%zu\n", key, vlen);

         leveldb_iter_next(iter);
      }

      leveldb_readoptions_destroy(readopts);
      leveldb_iter_destroy(iter);
   }

   char *prop = leveldb_property_value(db, "leveldb.stats");
   if (prop) {
      printf("prop='%s'\n", prop);
      free(prop);
   }

   leveldb_options_destroy(options);
   leveldb_close(db);

   return 0;
}

