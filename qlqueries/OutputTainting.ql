/**
 * @name Output Tainting 
 * @description Finding Outputs
 * @kind path-problem
 * @tags security
 * @id javascipt/dangerous
 * @precision medium 
 */

import javascript
import DataFlow::PathGraph

DataFlow::Node coreSources() { 
    result = DataFlow::moduleImport("@actions/core").getAMemberCall("getInput") or
    result = DataFlow::moduleImport("@actions/core").getAMemberCall("getMultilineInput")
}

DataFlow::Node outputSinks() {
    result = DataFlow::moduleImport("@actions/core").getAMemberCall("setOutput").getArgument(1) or
    result = DataFlow::moduleImport("@actions/core").getAMemberCall("exportVariable").getArgument(1) or
    //result = DataFlow::moduleImport("@actions/core").getAMemberCall("setSecret").getArgument(0) or
    result = DataFlow::moduleImport("@actions/core").getAMemberCall("saveState").getArgument(1)
}

class Configuration extends TaintTracking::Configuration {
    Configuration() {
        this = "OutputTainting"
    }

    override predicate isSource(DataFlow::Node source) {
        source = coreSources()
    }

    override predicate isSink(DataFlow::Node sink) {
	    sink = outputSinks() 
    }
}

from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink, CallExpr e, Expr arg, string argname, string fname
where cfg.hasFlowPath(source, sink) and
    e = source.getNode().asExpr() and
    arg = e.getArgument(0) and
    argname = sink.getNode().asExpr().getParent().(CallExpr).getArgument(0).getStringValue() and
    fname =  sink.getNode().asExpr().getParent().(CallExpr).getCalleeName()
select arg, source, sink, fname, argname