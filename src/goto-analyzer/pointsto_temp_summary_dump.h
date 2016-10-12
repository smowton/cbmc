#ifndef CPROVER_POINTS_TO_TEMP_SUMMARY_DUMP_H
#define CPROVER_POINTS_TO_TEMP_SUMMARY_DUMP_H

#include <summaries/summary_dump.h>
#include <iosfwd>


std::string  pointsto_temp_summary_dump_in_html(
    object_summaryt const  obj_summary,
    goto_modelt const&  program,
    std::ostream&  ostr
    );


#endif
