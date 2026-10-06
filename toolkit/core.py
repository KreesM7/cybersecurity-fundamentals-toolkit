from dataclasses import dataclass
from importlib import import_module, resources, util
from pathlib import Path
from typing import Callable
import pkgutil
import re
import sys


@dataclass(frozen=True)
class ModuleSpec:
    id: str
    title: str
    order: int
    create_panel: Callable


@dataclass(frozen=True)
class ModuleEntry:
    name: str
    spec: ModuleSpec | None
    error: str = ''
    readiness: Callable = lambda: ''


def discover_modules(paths=None) -> list[ModuleEntry]:
    if paths is None:
        package = import_module('toolkit.modules')
        candidates = [(name, None) for _, name, _ in pkgutil.iter_modules(package.__path__)]
    else:
        candidates = [(p.stem, p) for root in paths for p in Path(root).glob('*.py')]
    entries, seen = [], set()
    for name, path in sorted(candidates):
        if name.startswith('_'):
            continue
        try:
            if path is None:
                module = import_module('toolkit.modules.' + name)
            else:
                # A unique import name keeps temporary or external test modules isolated.
                module_name = '_toolkit_plugin_' + name + '_' + str(abs(hash(str(path))))
                loader = util.spec_from_file_location(module_name, path)
                module = util.module_from_spec(loader)
                sys.modules[module_name] = module
                loader.loader.exec_module(module)
            spec = module.MODULE
            if not isinstance(spec, ModuleSpec) or not re.fullmatch(r'[a-z][a-z0-9-]*', spec.id):
                raise ValueError('Expected a ModuleSpec with a stable lowercase id.')
            if not spec.title or not isinstance(spec.order, int) or not callable(spec.create_panel):
                raise ValueError('Invalid module title, order, or panel factory.')
            if spec.id in seen:
                raise ValueError('Duplicate module id: ' + spec.id)
            seen.add(spec.id)
            entries.append(ModuleEntry(name, spec, readiness=getattr(module, 'readiness', lambda: '')))
        except Exception as exc:
            entries.append(ModuleEntry(name, None, f'{type(exc).__name__}: {exc}'))
    return sorted(entries, key=lambda entry: (entry.spec.order if entry.spec else 1000, entry.name))


def resource_text(name: str) -> str:
    return resources.files('toolkit.resources').joinpath(name).read_text(encoding='utf-8')
