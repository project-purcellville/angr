import angr
from angr.analyses.decompiler.decompilation_options import PARAM_TO_OPTION
import logging

"""
Invoke this test script with the `pytest --insta` switch to enable the snapshot mechanism
"""

logging.basicConfig(level=logging.CRITICAL, force=True)


def analyze_binary(binary_path):
    """
    Run the binary through CFG generation and extract the decompilation from the Decompiler analysis.
    The intention of this analysis function is to use as little angr interfaces as possible since they may
    change over time. If they change, this script will need updating.
    """
    project = angr.Project(binary_path, auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True)
    decompilation = {}

    function: angr.knowledge_plugins.functions.function.Function
    for function in cfg.functions.values():
        function.normalize()

        # Wrapping in a try/except because the decompiler sometimes fails
        try:
            decomp = project.analyses.Decompiler(
                func=function,
                cfg=cfg,
                # setting show_casts to false because of non-determinism
                options=[
                    (
                        PARAM_TO_OPTION["structurer_cls"],
                        "Phoenix",
                    ),
                    (
                        PARAM_TO_OPTION["show_casts"],
                        False,
                    ),
                ],
            )
        except Exception as e:
            print(e)

        func_key = f"{function.addr}:{function.name}"

        if decomp.codegen:
            decompilation[func_key] = decomp.codegen.text
        else:
            decompilation[func_key] = None

    return decompilation


def test_functions_decompilation(binary, snapshot):
    analysis = analyze_binary(binary)
    assert snapshot(f"{binary.replace('/', '_')}.json") == analysis
