require 'casserver/authenticators/sql_encrypted'
require 'bcrypt'
require 'attr_encrypted'

class CASServer::Authenticators::SQLAttrEncrypted < CASServer::Authenticators::SQLEncrypted
  extend AttrEncrypted
  class << self
    def setup(options)
      super(options)
      user_model_name = "CASUser_AttrEncrypted_#{options[:auth_index]}"

      class_eval %{
        class #{user_model_name} < ActiveRecord::Base
        end
      }
      key = options[:encryption_key]
      raise "#{self} encryption key must be provided" if key.nil?
      @prefix = options[:prefix] || 'encrypted_'
      @fields = options[:fields]
      raise "#{self} if you are not encrypting fields other than password, use SQLEncrypted authenticator" if @fields.size == 0
      @user_model = const_get(user_model_name)
      @user_model.establish_connection(options[:database])
      @user_model.set_table_name(options[:user_table] || 'users')
      @user_model.inheritance_column = 'no_inheritance_column' if options[:ignore_type_column]
      if @fields.is_a? Array
        @fields.each do |field|
          set_encrypted_attribute(field, key)
        end
      elsif @fields.is_a? Hash
        @fields.each do |field, model_field|
          set_encrypted_attribute(model_field, key)
        end
      end
    end

    def fields
      @fields
    end

    def prefix
      @prefix
    end

    def set_encrypted_attribute(field, key)
      @user_model.send(:attr_encrypted, field.to_sym, :key => key, :prefix => @prefix)
    end

    def user_model
      @user_model
    end
  end

  def validate(credentials)
    read_standard_credentials(credentials)
    raise_if_not_configured

    user_model = self.class.user_model

    username_column = @options[:username_column] || "encrypted_username"
    encrypted_username_column = @options[:encrypted_username_column] || true

    $LOG.debug "#{self.class}: [#{user_model}] " + "Connection pool size: #{user_model.connection_pool.instance_variable_get(:@checked_out).length}/#{user_model.connection_pool.instance_variable_get(:@connections).length}"
    results = if encrypted_username_column
      user_model.where(username_column => user_model.encrypt(username_column.gsub(self.class.prefix, '').to_sym, @username))
    else
      user_model.where(username_column => @username)
    end

    user_model.connection_pool.checkin(user_model.connection)

    if results.size > 0
      user = results.first
      unless @options[:extra_attributes].blank?
        if results.size > 1
          $LOG.warn("#{self.class}: Unable to extract extra_attributes because multiple matches were found for #{@username.inspect}")
        else
          extract_extra(user)
          log_extra
        end
      end
      user.password_digest == ::BCrypt::Engine.hash_secret("#{@password}", ::BCrypt::Password.new(user.password_digest).salt)
    else
      false
    end
  end

private

  def extract_extra(user)
    @extra_attributes = {}
    attribs = extra_attributes_to_extract
    if self.class.fields.is_a? Array
      attribs.each do |col|
        @extra_attributes[col] = [user.send(col)]
      end
    elsif self.class.fields.is_a? Hash
      attribs.each do |col|
        col_name = self.class.fields[col]
        value = user.send(col_name || col)
        @extra_attributes[col] = [value]
      end
    end
  end

end