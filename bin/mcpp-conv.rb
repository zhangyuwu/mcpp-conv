#!/usr/bin/ruby

require 'klib'
require 'set'
require 'fileutils'

class Rule
    attr_reader :name
    attr_reader :pattern
    attr_reader :replace_with

    def initialize(name, pattern, replace_with, scan_action = nil)
        @name = name
        @pattern = pattern
        @replace_with = replace_with.gsub("$", "\\")
        @scan_action = scan_action
    end
    
    def apply(str)
        str.gsub(pattern, replace_with)
    end
    
    def scan(str)
        str.match_all(pattern) { |m|
            if @scan_action.not_nil?
                @scan_action.call(m)
            end
        }
    end
    
    def to_s
        [ "Name: #{name}", "Pattern: #{pattern}" ].join("\n")
    end
end

class RuleSet < Array   
    def apply(content)
        sw = StringIO.new
        content.each_line { |line|
            if not line.strip.start_with?('//')
                self.each { |rule|
                    line = rule.apply(line)
                }
            end
            sw.puts(line)
        }
        return sw.string
    end
    
    def scan(content)
        content.each_line { |line|
            if not line.strip.start_with?('//')
                self.each { |rule|
                    rule.scan(line)
                }
            end
        }
    end
end

class ManagedTypeSet < Set
    def add(name)
        if name != nil && !name.empty? && name != 'void'
            super(name)
        end
    end
end

class ManagedCppConverter
    ID              = '\b[A-Za-z_]\w*\b'
    VAR             = '((\b[A-za-z_]\w*\-\>)*[A-za-z_]\w*)'
    NUM             = '\b\d+\b'
    FUNC_ID         = '\b[A-Za-z_]\w*(::\w*)*\b'
    ID_OR_NUM       = "#{ID}|#{NUM}"
    VAR_OR_NUM      = "#{VAR}|#{NUM}"
    ACCESS_LEVEL    = 'public|private|protected'
    
    attr_accessor :managed_types

    def initialize(user_managed_types = nil)
        @managed_types = ManagedTypeSet.new(['System::\b[\w:]+'])
        if not user_managed_types.nil?
            user_managed_types.each { |type| @managed_types.add(type) }
        end
    end
    
    def managed_type_decl_rules
        [
            Rule.new(
                'Class/Struct Forward',
                /(__(?<seal1>sealed)\s+)?((?<access>#{ACCESS_LEVEL})\s+)?(__(?<abs1>abstract)\s+)?__gc\s+(__(?<seal2>sealed)\s+)?(__(?<abs2>abstract)\s+)?(?<class>class|struct)\s+(?<name>\w+)\s*;/,
                'ref \k<class> \k<name>;',
                lambda { |m|
                    @managed_types.add(m['name'])
                }
            ),

            Rule.new(
                'Class/Struct Declaration',
                /(__(?<seal1>sealed)\s+)?((?<access>#{ACCESS_LEVEL})\s+)?(__(?<abs1>abstract)\s+)?__gc\s+(__(?<seal2>sealed)\s+)?(__(?<abs2>abstract)\s+)?(?<class>class|struct)\s+(?<name>\w+)/,
                '\k<access> ref \k<class> \k<name> \k<seal1>\k<seal2>\k<abs1>\k<abs2>',
                lambda { |m|
                    @managed_types.add(m['name'])
                }
            ),

            Rule.new(
                'Interface Forward',
                /\b((?<access>#{ACCESS_LEVEL})\s+)?__gc\s+(__)?interface\s+(?<id>#{ID})\s*;/,
                'interface class \k<id>;',
                lambda { |m|
                    @managed_types.add(m['id'])
                }
            ),

            Rule.new(
                'Interface Declaration',
                /\b((?<access>#{ACCESS_LEVEL})\s+)?__gc\s+(__)?interface\s+(?<id>#{ID})/,
                '\k<access> interface class \k<id>',
                lambda { |m|
                    @managed_types.add(m['id'])
                }
            ),

            Rule.new(
                'Delegate Declarations',
                /\b((?<access>#{ACCESS_LEVEL})\s+)?__delegate\s+(?<return-type>.*)\s+(?<id>#{ID})\s*\((?<args>[^()]*)\)/,
                '\k<access> delegate \k<return-type> \k<id>(\k<args>)',
                lambda { |m|
                    @managed_types.add(m['id'])
                }
            ),
        ]
    end
    
    def syntax_rules
        return managed_type_decl_rules + [
            Rule.new(
                'Value Class/Struct Declaration',
                /\b(__value)\s+(?<class>class|struct)\b/,
                'value \k<class>'
            ),

            Rule.new(
                'Enum Declaration',
                /\b((?<access>#{ACCESS_LEVEL})\s+)?__value\s+enum\s+(?<name>#{ID})/,
                '\k<access> enum class \k<name>'
            ),

            Rule.new(
                'Event Declaration',
                /\b(__event)\s+(?<type>[\w\:]+)\s{0,}[\*\^]\s*(?<name>#{ID})/,
                'event \k<type> ^ \k<name>'
            ),

            Rule.new(
                'Managed String',
                /\bS("[^\"]*")/,
                "$1"
            ),

            Rule.new(
                'Boxing',
                /\b__box\b/,
                ""
            ),

            Rule.new(
                '__typeof',
                /\b__typeof\b/,
                "typeid"
            ),

            Rule.new(
                '__try_cast',
                /\b__try_cast\b/,
                "safe_cast"
            ),

            Rule.new(
                '__pin',
                /\b__pin\b/,
                "pin_ptr"
            ),

            Rule.new(
                'NULL',
                /\bNULL\b/,
                "nullptr"
            ),

            Rule.new(
                'Managed byte array: unsigned char buffer __gc []',
                /\b(?<type>(unsigned\s+)?(char|short|int|long))\s+(?<varname>[A-Za-z_]\w+)\s+__gc\s*\[\s*\]/,
                'cli::array<\k<type>>^ \k<varname>'
            ),

            Rule.new(
                'Managed byte array new: new unsigned char __gc [x]',
                /\bnew\s+(?<type>(unsigned\s+)?(char|short|int|long))\s+__gc\s*\[\s*(?<number>#{ID_OR_NUM})\s*\]/,
                'gcnew cli::array<\k<type>>(\k<number>)'
            ),

            Rule.new(
                'Remove __gc,__nogc',
                /\b(__gc|__nogc)\b\s*/,
                ''
            ),
        ]
    end

    def managed_type_using_rules
        pattern = @managed_types.to_a.join('|')
        type = "(?<type>\\b([\\w:]*::)?(#{pattern})\\b)"
        
        return [
            Rule.new(
                'Array Function',
                /#{type}\s*\*\s*(?<id>#{FUNC_ID})\s*(?<args>\(.*\))\s*\[\s*\](?<rest>.*)/,
                'cli::array<\k<type> ^>^ \k<id>\k<args>\k<rest>'
            ),

            Rule.new(
                'Array Decl(ref): System::Data::DataColumn * PrimaryKey[]',
                /#{type}\s*\*\s*(?<id>#{ID})\s*\[\s*\]/,
                'cli::array<\k<type> ^>^ \k<id>'
            ),

            Rule.new(
                'Array Decl(val): System::Drawing::PointF points[]',
                /#{type}\s*(?<id>#{ID})\s*\[\s*\]/,
                'cli::array<\k<type>>^ \k<id>'
            ),

            Rule.new(
                'Var Decl: System::String __gc * p',
                /#{type}(\s+__gc)?\s*\*\s*(?<id>#{ID})/,
                '\k<type> ^ \k<id>'
            ),
            
            Rule.new(
                'Array New(ref): new Object * [N]',
                /\bnew\s+#{type}\s*\*\s*\[\s*(?<n>#{VAR_OR_NUM})\s*\]/,
                'gcnew cli::array<\k<type> ^>(\k<n>)'
            ),

            Rule.new(
                'Array New(val): new ValueType [N]',
                /\bnew\s+#{type}\s*\[\s*(?<n>#{VAR_OR_NUM})\s*\]/,
                'gcnew cli::array<\k<type>>(\k<n>)'
            ),
            
            Rule.new(
                'Var New',
                /\bnew\s+#{type}(?=\s*($|\(.*\)))/,
                'gcnew \k<type>'
            ),
            
            Rule.new(
                'Argument in template',
                /\<\s*#{type}\s*\*\s*\>/,
                '<\k<type> ^>'
            ),

            Rule.new(
                'Argument in ()',
                /\(\s*#{type}\s*\*\s*\)/,
                '(\k<type> ^)'
            ),
        ]
    end

    def property_impl_rules
        return [
            Rule.new(
                'Property Impl: bool File::get_Exists()',
                /(?<return-type>[\w\<\>\:\s\^]+[\s\^])((?<classname>[\w\:]+)::(?<method>[gs]et)_(?<property>[A-Z]\w*))\s*(?<args>\([\w\s\^\:]*\))/,
                '\k<return-type>\k<classname>::\k<property>::\k<method>\k<args>'
            ),
        ]
    end
    
    # scan managed types
    def scan(content)
        RuleSet.new(managed_type_decl_rules).scan(content)
    end
    
    def convert(content)
        content = RuleSet.new(syntax_rules).apply(content)
        content = RuleSet.new(managed_type_using_rules).apply(content)
        content = RuleSet.new(property_impl_rules).apply(content)
        content = PropertyDeclConverter.new.convert(content)
        return content
    end
end

class PropertyDeclConverter
    COMMENTS = '(?<comments>\s*\/\/[^\r\n]*$)'
    METADATA = '(?<metadata>\s*\[[^\r\n]*\]$)'
    PROPERTY = '\s*\b__property\s+(?<return-type>[^\(\)]*[\*\^\s])(?<method>[gs]et)_(?<property-name>[A-Za-z]\w*)\s{0,}\((?<arguments>[^\(\)]*)\)\s*(?<code-block>(;|\[\s*\]\s*;|\{(?:[^{}]*|\g<code-block>)+\}(\s*;)?))?'
    BLANKLINE = '(\s*$)'

    class PropertyMethod
        attr_accessor :name
        attr_accessor :method
        attr_accessor :return_type
        attr_accessor :arguments
        attr_accessor :comments
        attr_accessor :metadata
        attr_accessor :code_block
        
        def get_args(arguments)
            regex = /(?<type>.*[\*\^\s]|\w+)(?<param>\b\w+\b)?/
            arguments.split(',').map { |s|
                m = regex.match(s)
                [(m['type'] || '').strip, (m['param'] || '').strip]
            }
        end
        
        def data_type
            if method == 'get'
                return return_type
            else
                return get_args(@arguments).last[0]
            end
        end
        
        def index_type
            args = get_args(@arguments)
            if args.empty? || (method == 'set' && args.count == 1)
                return nil
            else
                return args.first[0]
            end
        end
    end
    
    class PropertyInfo
        attr_accessor :getter
        attr_accessor :setter
        
        def name
            (getter || setter).name
        end
        
        def metadata
            (getter || setter).metadata
        end
        
        def data_type
            (getter || setter).data_type
        end
        
        def index_type
            (getter || setter).index_type
        end
    end
    
    class PropertySet < Hash
        def trim(s)
            s.nil? ? nil : s.strip
        end
        
        def load(content)
            r = /^#{COMMENTS}?#{METADATA}?#{PROPERTY}/
            content.match_all(r) { |m|
                pm = PropertyMethod.new
                pm.comments = trim m['comments']
                pm.metadata = trim m['metadata']
                pm.name = trim m['property-name']
                pm.return_type = trim m['return-type']
                pm.method = trim m['method']
                pm.arguments = trim m['arguments']
                pm.code_block = trim m['code-block']
                
                key = "#{pm.name}[#{pm.index_type}]"
                prop_info = self[key] || PropertyInfo.new
                if pm.method == 'get'
                    prop_info.getter = pm
                else
                    prop_info.setter = pm
                end
                self[key] = prop_info
            }
            
            @indent = '  '
        end
        
        def to_s
            sw = StringIO.new
            each_value { |prop_info|
                sw.puts
                if prop_info.metadata
                    sw.puts "#{@indent}#{prop_info.metadata}"
                end
                
                if prop_info.index_type
                    sw.puts("#{@indent}property #{prop_info.data_type} #{prop_info.name}[#{prop_info.index_type}] {");
                else
                    sw.puts("#{@indent}property #{prop_info.data_type} #{prop_info.name} {");
                end

                methods = [prop_info.getter, prop_info.setter].select { |x| not x.nil? }
                methods.each.with_index { |method, index|
                    if method.comments
                        sw.puts "#{@indent}  #{method.comments}"
                    end
                    return_type = method.return_type
                    return_type = return_type.gsub(/\b(static)\b\s*/, '')
                    sw.puts("#{@indent}  #{return_type} #{method.method}(#{method.arguments})#{method.code_block == ';' ? '' : ' '}#{method.code_block}");
                    if index + 1 < methods.count
                        sw.puts
                    end
                }
                
                sw.puts("#{@indent}}");
                sw.puts
            }
            return sw.string
        end
    end

    def convert(content)
        prop_block_pat = /^(#{COMMENTS}?#{METADATA}?#{PROPERTY}#{BLANKLINE}*)+/m        
        content.gsub(prop_block_pat) { |s|
            ps = PropertySet.new
            ps.load(s)
            ps.to_s
        }
    end
end

def conv(src_dir, dest_dir, managed_types_file)
    if dest_dir.nil?
        dest_dir = Dir.pwd
    end
    
    if not Dir.exist?(dest_dir)
        Dir.mkdir(dest_dir)
    end
    
    # load user defined managed types, skip empty lines and comments begin with '#'
    if managed_types_file.not_nil? && File.exist?(managed_types_file)
        managed_types = IO.readlines(managed_types_file).map { |s| s.strip }.select { |s| !(s.start_with?('#') || s.empty?) }
    end
    
    files = Dir.glob(File.join(File.unixpath(src_dir), '*.{h,cpp,C}')).map { |path| [path, File.join(dest_dir, File.basename(path))] }
    conv = ManagedCppConverter.new(managed_types)
    
    # scan managed types first
    files.each { |src, dest|
        content = File.read(src).to_utf8
        conv.scan(content)
    }
    
    # output managed types
    puts "*** Managed Types ***"
    conv.managed_types.to_a.each.with_index { |s, i| puts "#{i+1}. #{s}" }
    puts
    
    # do conversion
    files.each { |src, dest|
        puts "Convert #{src}..."
        content = File.read(src).to_utf8
        content = conv.convert(content)
        FileUtils.move(src, src + '.bak') if File.absolute_path(src) == File.absolute_path(dest)
        File.write(dest, content)
    }
end

class CppConvCmdOptions < BaseCmdParams
    def declare_options
        [
            option(name: 'src_dir', syntax: '[--src-dir] DIRECTORY', desc: 'Input directory contains manged C++ files', validator: lambda {|v| [v.not_nil?, 'required']}),
            option(name: 'dest_dir', syntax: '[--dest-dir] DIRECTORY', desc: 'Output directory to store converted C++/CLI files'),
            option(name: 'managed_types', syntax: '--managed-types FILENAME', desc: 'A text file with user defined managed types'),
            option(name: 'help', syntax: '--help'),
        ]
    end
end

def main
    param = CppConvCmdOptions.new
    begin
        param.parse!(ARGV)
        if param.help
            puts param.usage
        else
            param.validate
            conv(param.src_dir, param.dest_dir, param.managed_types)
        end
    end
end

main
