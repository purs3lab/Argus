/**
 * @name Context Sinks
 * @description Finding sinks for context
 * @kind path-problem
 * @tags security
 * @id javascipt/dangerous
 * @precision medium
 */

import javascript
import DataFlow::PathGraph

DataFlow::Node mainDangerCalls() {
    result = DataFlow::globalVarRef("eval").getACall().getArgument(0) or
    result = DataFlow::globalVarRef("setTimeout").getACall().getArgument(0) or
    result = DataFlow::globalVarRef("setInterval").getACall().getArgument(0) or
    result = DataFlow::globalVarRef("unserialize").getACall().getArgument(0)
}

DataFlow::Node execActionCalls() {
    result = DataFlow::moduleImport("@actions/exec").getAMemberCall("exec").getArgument(0)
}

DataFlow::Node childPrcocessCalls() {
    result = DataFlow::moduleImport("child_process").getAMemberCall("exec").getArgument(0) or
    result = DataFlow::moduleImport("child_process").getAMemberCall("execSync").getArgument(0) or
    result = DataFlow::moduleImport("child_process").getAMemberCall("execFile").getArgument(0) or
    result = DataFlow::moduleImport("child_process").getAMemberCall("execFileSync").getArgument(0) or
    result = DataFlow::moduleImport("child_process").getAMemberCall("spawn").getArgument(0) or
    result = DataFlow::moduleImport("child_process").getAMemberCall("spawnSync").getArgument(0)
}

DataFlow::Node pullrequestSources() {
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("pull_request").getAPropertyRead("head").getAPropertyRead("ref") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("pull_request").getAPropertyRead("head").getAPropertyRead("label") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("pull_request").getAPropertyRead("title") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("pull_request").getAPropertyRead("body")
}

DataFlow::Node issueSources() {
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("issue").getAPropertyRead("title") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("issue").getAPropertyRead("body")
}

DataFlow::Node discussionSources() {
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("discussion").getAPropertyRead("title") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("discussion").getAPropertyRead("body")
}

DataFlow::Node commentSources() {
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("comment").getAPropertyRead("body") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("review").getAPropertyRead("body") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("review_comment").getAPropertyRead("body")
}

DataFlow::Node workflowRunSources() {
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("workflow_run").getAPropertyRead("head_branch") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("workflow_run").getAPropertyRead("head_commit").getAPropertyRead("message") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("workflow_run").getAPropertyRead("head_commit").getAPropertyRead("author").getAPropertyRead("name") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("workflow_run").getAPropertyRead("head_commit").getAPropertyRead("author").getAPropertyRead("email") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("workflow_run").getAPropertyRead("head_commit").getAPropertyRead("pull_requests").getAPropertyRead().getAPropertyRead("head").getAPropertyRead("ref") 
}

DataFlow::Node headCommitSources() {
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("head_commit").getAPropertyRead("message") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("head_commit").getAPropertyRead("author").getAPropertyRead("name") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("head_commit").getAPropertyRead("author").getAPropertyRead("email") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("commits").getAPropertyRead().getAPropertyRead("message") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("commits").getAPropertyRead().getAPropertyRead("author").getAPropertyRead("name") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("commits").getAPropertyRead().getAPropertyRead("author").getAPropertyRead("email") 
}



class MyConfiguration extends TaintTracking::Configuration {
    MyConfiguration() {
        this = "ContextSinks"
    }

    override predicate isSource(DataFlow::Node source) {
        source = pullrequestSources() or
        source = issueSources() or
        source = discussionSources() or
        source = workflowRunSources() or
        source = commentSources() or
        source = headCommitSources()
    }

    override predicate isSink(DataFlow::Node sink) {
	    sink = mainDangerCalls() or
        sink = execActionCalls() or
        sink = childPrcocessCalls()
    }
}

from MyConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink, Expr arg, string test
where cfg.hasFlowPath(source, sink) and
    source.getNode().asExpr() = arg and
    test = sink.getNode().asExpr().getParent().(CallExpr).getCalleeName()
select arg, source, sink, test
