project('libb2', 'c', version: '0.98.1',
  meson_version: '>=0.47.0',
  default_options: ['optimization=3'])

openmp = dependency('openmp', required: get_option('openmp'))

conf = configuration_data()
cc = meson.get_compiler('c')

testcode = '''
int main() {
    __builtin_cpu_init();
    return !__builtin_cpu_supports ("@0@");
}
'''

fat = get_option('fat')
native = get_option('native') and not fat

if fat or native
  foreach iset: ['avx', 'avx2', 'sse2', 'ssse3', 'sse4.1', 'xop']
    arg = '-m'+iset
    has_arg = cc.has_argument(arg)
    if fat and not has_arg
      error('fat binary but compiler does not support "@0@"'.format(arg))
    elif native and has_arg and cc.run(testcode.format(iset)).returncode() == 0
      add_project_arguments(arg, language: 'c')
      # this is technically unnecessary as blake2-config.h additionally defines it
      # based on gcc builtin __<iset>__ once -m<iset> is added
      conf.set('HAVE_' + iset.underscorify().to_upper(), true)
    endif
  endforeach
endif

if host_machine.endian() == 'little'
  conf.set('NATIVE_LITTLE_ENDIAN', true)
endif

use_sse = conf.get('HAVE_SSSE3', false)

subdir('src')
