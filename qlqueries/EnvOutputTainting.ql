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
    result = DataFlow::globalVarRef("process").getAPropertyRead("env").getAPropertyReference()
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

from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink, IndexExpr e, DotExpr d, string name, string fname, string argname
where cfg.hasFlowPath(source, sink) and
    ((e = source.getNode().asExpr() and name = e.getPropertyName()) or
    (d = source.getNode().asExpr() and name = d.getPropertyName())) and
    argname = sink.getNode().asExpr().getParent().(CallExpr).getArgument(0).getStringValue() and
    fname =  sink.getNode().asExpr().getParent().(CallExpr).getCalleeName()
select name, source, sink, fname, argname