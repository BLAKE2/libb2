configure_file(output: 'config.h', configuration: conf)

sources = files(
  'blake2sp.c',
  'blake2bp.c',
)

if false # the code uses defines, not separate files
  simd_mod = import('unstable-simd')
  libb2_simd = simd_mod.check('blake2b',
    sse2: 'blake2b-sse2.c',
    ssse3: 'blake2b-ssse3.c',
    sse41: 'blake2b-sse41.c',
    avx: 'blake2b-avx.c',
    # xop is not available in meson
  )
endif

internal_libs = []

if get_option('fat')
  sources += files(
    'blake2-dispatch.c',
  )
  internal_libs += [
    static_library('blake2_ref',
      'blake2b-ref.c', 'blake2s-ref.c',
      c_args: ['-DSUFFIX=_ref']
    ),
    static_library('blake2_sse2',
      'blake2b.c', 'blake2s.c',
      c_args: ['-DSUFFIX=_sse2', '-msse2']
    ),
    static_library('blake2_ssse3',
      'blake2b.c', 'blake2s.c',
      c_args: ['-DSUFFIX=_ssse3', '-msse2', '-mssse3']
    ),
    static_library('blake2_sse4.1',
      'blake2b.c', 'blake2s.c',
      c_args: ['-DSUFFIX=_sse41', '-msse2', '-mssse3', '-msse4.1']
    ),
    static_library('blake2_avx',
      'blake2b.c', 'blake2s.c',
      c_args: ['-DSUFFIX=_avx', '-msse2', '-mssse3', '-msse4.1', '-mavx']
    ),
    static_library('blake2_xop',
      'blake2b.c', 'blake2s.c',
      c_args: ['-DSUFFIX=_xop', '-msse2', '-mssse3', '-msse4.1', '-mavx', '-mxop']
    ),
  ]
elif use_sse
  sources += files(
    'blake2s.c',
    'blake2b.c',
  )
else
  sources += files(
    'blake2s-ref.c',
    'blake2b-ref.c',
  )
endif

install_headers('blake2.h')
libb2 = library('b2', sources,
  c_args: '-DSUFFIX=',
  link_with: internal_libs,
  version: '1.0.4',
  install: true,
)

libb2_dep = declare_dependency(
  link_with: libb2,
  include_directories: include_directories('.')
)
import('pkgconfig').generate( #libb2, # requires meson_version 0.46, not in Ubuntu 18.04
  name: 'libb2',
  libraries: libb2, # implied in 0.46
  version: meson.project_version(), # implied in 0.46
  description: 'C library providing BLAKE2b, BLAKE2s, BLAKE2bp, BLAKE2sp',
  url: 'https://github.com/BLAKE2/libb2',
)

foreach t: ['2s', '2b', '2sp', '2bp']
  name = 'blake'+t+'-test'
  testprog = executable(name, name+'.c', link_with: libb2)
  test(name, testprog)
endforeach
