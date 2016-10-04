#ifndef JSON_IREP_H
#define JSON_IREP_H

#include "json.h"
#include "irep.h"

json_objectt irep_to_json(const irept&);
irept irep_from_json(const jsont&);

#endif
