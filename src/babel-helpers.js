// Normalised bodies of the genuine Babel interop helpers, harvested from real
// Babel output in the Phase 3 corpus (@babel/helpers, @babel/runtime, babel 6
// and 7 compiled packages). Normalisation: all whitespace removed and the
// function name reduced to its base name (Babel may add a numeric suffix).
// Only these exact bodies are trusted; anything else is a look-alike and the
// wrapped require stays an escape. Variants that call other injected helpers
// (core-js _typeof / _Object$defineProperty) are deliberately not listed.

export const GENUINE_HELPERS = {
  "_interopRequireDefault": [
    "function_interopRequireDefault(obj){returnobj&&obj.__esModule?obj:{default:obj};}",
    "function_interopRequireDefault(obj){returnobj&&obj.__esModule?obj:{\"default\":obj};}",
    "function_interopRequireDefault(t){returnt&&t.__esModule?t:{default:t}}"
  ],
  "_interopRequireWildcard": [
    "function_interopRequireWildcard(obj){if(obj&&obj.__esModule){returnobj;}else{varnewObj={};if(obj!=null){for(varkeyinobj){if(Object.prototype.hasOwnProperty.call(obj,key)){vardesc=Object.defineProperty&&Object.getOwnPropertyDescriptor?Object.getOwnPropertyDescriptor(obj,key):{};if(desc.get||desc.set){Object.defineProperty(newObj,key,desc);}else{newObj[key]=obj[key];}}}}newObj.default=obj;returnnewObj;}}",
    "function_interopRequireWildcard(obj){if(obj&&obj.__esModule){returnobj;}else{varnewObj={};if(obj!=null){for(varkeyinobj){if(Object.prototype.hasOwnProperty.call(obj,key))newObj[key]=obj[key];}}newObj.default=obj;returnnewObj;}}",
    "function_interopRequireWildcard(obj,nodeInterop){if(!nodeInterop&&obj&&obj.__esModule){returnobj;}if(obj===null||typeofobj!==\"object\"&&typeofobj!==\"function\"){return{default:obj};}varcache=_getRequireWildcardCache(nodeInterop);if(cache&&cache.has(obj)){returncache.get(obj);}varnewObj={};varhasPropertyDescriptor=Object.defineProperty&&Object.getOwnPropertyDescriptor;for(varkeyinobj){if(key!==\"default\"&&Object.prototype.hasOwnProperty.call(obj,key)){vardesc=hasPropertyDescriptor?Object.getOwnPropertyDescriptor(obj,key):null;if(desc&&(desc.get||desc.set)){Object.defineProperty(newObj,key,desc);}else{newObj[key]=obj[key];}}}newObj.default=obj;if(cache){cache.set(obj,newObj);}returnnewObj;}",
    "function_interopRequireWildcard(obj,nodeInterop){if(!nodeInterop&&obj&&obj.__esModule){returnobj;}if(obj===null||(typeofobj!==\"object\"&&typeofobj!==\"function\")){return{default:obj}}varcache=_getRequireWildcardCache(nodeInterop);if(cache&&cache.has(obj)){returncache.get(obj);}varnewObj={};varhasPropertyDescriptor=Object.defineProperty&&Object.getOwnPropertyDescriptor;for(varkeyinobj){if(key!==\"default\"&&Object.prototype.hasOwnProperty.call(obj,key)){vardesc=hasPropertyDescriptor?Object.getOwnPropertyDescriptor(obj,key):null;if(desc&&(desc.get||desc.set)){Object.defineProperty(newObj,key,desc);}else{newObj[key]=obj[key];}}}newObj.default=obj;if(cache){cache.set(obj,newObj);}returnnewObj;}"
  ],
  "_getRequireWildcardCache": [
    "function_getRequireWildcardCache(nodeInterop){returnnodeInterop?cacheNodeInterop:cacheBabelInterop;}",
    "function_getRequireWildcardCache(nodeInterop){if(typeofWeakMap!==\"function\")returnnull;varcacheBabelInterop=newWeakMap();varcacheNodeInterop=newWeakMap();return(_getRequireWildcardCache=function(nodeInterop){returnnodeInterop?cacheNodeInterop:cacheBabelInterop;})(nodeInterop);}",
    "function_getRequireWildcardCache(nodeInterop){if(typeofWeakMap!==\"function\")returnnull;varcacheBabelInterop=newWeakMap();varcacheNodeInterop=newWeakMap();return(_getRequireWildcardCache=function_getRequireWildcardCache(nodeInterop){returnnodeInterop?cacheNodeInterop:cacheBabelInterop;})(nodeInterop);}"
  ]
};
