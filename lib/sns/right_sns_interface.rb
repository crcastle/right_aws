#
# Copyright (c) 2007-2008 RightScale Inc
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

module RightAws

  #
  # Right::Aws::SnsInterface - RightScale's low-level Amazon SNS interface
  #

  class SnsInterface < RightAwsBase
    include RightAwsBaseInterface
    
    API_VERSION       = "2010-03-31"
    DEFAULT_HOST      = "sns.us-east-1.amazonaws.com"
    DEFAULT_PORT      = 443
    DEFAULT_PROTOCOL  = 'https'
    REQUEST_TTL       = 30
    DEFAULT_VISIBILITY_TIMEOUT = 30


    @@bench = AwsBenchmarkingBlock.new
    def self.bench_xml
      @@bench.xml
    end
    def self.bench_sns
      @@bench.service
    end

    @@api = API_VERSION
    def self.api 
      @@api
    end

    # Creates a new SnsInterface instance. This instance is limited to
    # operations on SNS objects created with Amazon's 2008-01-01 API version.  This
    # interface will not work on objects created with prior API versions.  See
    # Amazon's article "Migrating to Amazon SNS API version 2008-01-01" at:
    # http://developer.amazonwebservices.com/connect/entry.jspa?externalID=1148
    #
    #  sqs = RightAws::SnsInterface.new('1E3GDYEOGFJPIT75KDT40','hgTHt68JY07JKUY08ftHYtERkjgtfERn57DFE379', {:multi_thread => true, :logger => Logger.new('/tmp/x.log')}) 
    #  
    # Params is a hash:
    #
    #    {:server       => 'sns.us-east-1.amazonaws.com' # Amazon service host: 'sns.us-east-1.amazonaws.com' (default)
    #     :port         => 443                   # Amazon service port: 80 or 443 (default)
    #     :multi_thread => true|false            # Multi-threaded (connection per each thread): true or false (default)
    #     :signature_version => '0'              # The signature version : '0', '1' or '2'(default)
    #     :logger       => Logger Object}        # Logger instance: logs to STDOUT if omitted }
    #
    def initialize(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
      init({ :name             => 'SNS', 
             :default_host     => ENV['SNS_URL'] ? URI.parse(ENV['SNS_URL']).host   : DEFAULT_HOST, 
             :default_port     => ENV['SNS_URL'] ? URI.parse(ENV['SNS_URL']).port   : DEFAULT_PORT, 
             :default_protocol => ENV['SNS_URL'] ? URI.parse(ENV['SNS_URL']).scheme : DEFAULT_PROTOCOL }, 
           aws_access_key_id     || ENV['AWS_ACCESS_KEY_ID'], 
           aws_secret_access_key || ENV['AWS_SECRET_ACCESS_KEY'], 
           params)
    end


  #-----------------------------------------------------------------
  #      Requests
  #-----------------------------------------------------------------

    # Generates a request hash for the query API
    def generate_request(action, param={})  # :nodoc:
      # For operation requests on a topic, the queue URI will be a parameter,
      # so we first extract it from the call parameters.  Next we remove any
      # parameters with no value or with symbolic keys.  We add the header
      # fields required in all requests, and then the headers passed in as
      # params.  We sort the header fields alphabetically and then generate the
      # signature before URL escaping the resulting query and sending it.
      service = param[:queue_url] ? URI(param[:queue_url]).path : '/'
      param.each{ |key, value| param.delete(key) if (value.nil? || key.is_a?(Symbol)) }
      service_hash = { "Action"           => action,
                       "Expires"          => (Time.now + REQUEST_TTL).utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "AWSAccessKeyId"   => @aws_access_key_id,
                       "Version"          => API_VERSION }
      service_hash.update(param)
      service_params = signed_service_params(@aws_secret_access_key, service_hash, :get, @params[:server], service)
      request        = Net::HTTP::Get.new("#{AwsUtils.URLencode(service)}?#{service_params}")
        # prepare output hash
      { :request  => request, 
        :server   => @params[:server],
        :port     => @params[:port],
        :protocol => @params[:protocol] }
    end

    def generate_post_request(action, param={})  # :nodoc:
      service = param[:queue_url] ? URI(param[:queue_url]).path : '/'
      message   = param[:message]                # extract message body if nesessary
      param.each{ |key, value| param.delete(key) if (value.nil? || key.is_a?(Symbol)) }
      service_hash = { "Action"           => action,
                       "Expires"          => (Time.now + REQUEST_TTL).utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "AWSAccessKeyId"   => @aws_access_key_id,
                       "MessageBody"      => message,
                       "Version"          => API_VERSION }
      service_hash.update(param)
      #
      service_params = signed_service_params(@aws_secret_access_key, service_hash, :post, @params[:server], service)
      request        = Net::HTTP::Post.new(AwsUtils::URLencode(service))
      request['Content-Type'] = 'application/x-www-form-urlencoded' 
      request.body = service_params
        # prepare output hash
      { :request  => request, 
        :server   => @params[:server],
        :port     => @params[:port],
        :protocol => @params[:protocol] }
    end


      # Sends request to Amazon and parses the response
      # Raises AwsError if any banana happened
    def request_info(request, parser) # :nodoc:
      request_info_impl(:sqs_connection, @@bench, request, parser)
    end

      # Creates a new topic, returning the new Topic object.
      #
      #  sqs.create_topic('my_awesome_queue') #=> 'https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue'
      #
    def create_topic(sns, topic_name)
      req_hash = generate_request('CreateTopic', 'Name' => topic_name)
      arn = request_info(req_hash, SnsCreateTopicParser.new(:logger => @logger))
      Sns::Topic.new(sns, arn)
    rescue
      on_exception
    end

     # Lists all topics owned by this user
     # Topic creation is an eventual operation and created topics may not show up in immediately subsequent list_topic calls.
     #
     #  sns.list_topics() #=> ['ZZ7XXXYYYBINS','ZZ7XXXYYYBINS']
     #
    def list_topics
      req_hash = generate_request('ListTopics')
      request_info(req_hash, SnsListTopicsParser.new(:logger => @logger))
    rescue
      on_exception
    end
      
      # Deletes topic. Any messages in the topic are permanently lost. 
      # Returns +true+ or an exception.
      # Deletion is eventual.
      #
      #  sns.delete_topic('arn:aws:sns:us-east-1:464646271962:test') #=> true
      # 
    def delete_topic(topic_arn)
      req_hash = generate_request('DeleteTopic', 'TopicArn' => topic_arn)
      request_info(req_hash, SnsStatusParser.new(:logger => @logger))
    rescue
      on_exception
    end
    
      # Sends a new message to a topic.  Body size is limited to 8 KB.
      # If successful, this call returns true
      #
      #  sns.send_message('arn:aws:sns:us-east-1:464646271962:test', 'body', 'message 1') #=> true
      #
      # On failure, send_message raises an exception.
      #
    def send_message(topic_arn, body, subject = nil)
      params = { 'TopicArn' => topic_arn, 'Message' => body }
      params.merge!({ 'Subject' => subject }) unless !subject || subject.length == 0
      req_hash = generate_post_request('Publish', params)
      request_info(req_hash, SnsStatusParser.new(:logger => @logger))
    rescue
      on_exception
    end

      # Same as send_message
    alias_method :push_message, :send_message

      # Retrieves the topic attribute(s). Returns a hash of attribute(s) or an exception.
    def get_topic_attributes(topic_arn)
      req_hash = generate_request('GetTopicAttributes', 'TopicArn' => topic_arn)
      request_info(req_hash, SnsGetTopicAttributesParser.new(:logger => @logger))
    rescue
      on_exception
    end
    
      # Retrieves the topic subscribers(s). Returns a hash containing a :set of members and the :next token
    def list_subscriptions_by_topic(topic_arn, next_token = nil)
      params = { 'TopicArn' => topic_arn }
      params.merge!({ 'NextToken' => next_token }) unless !next_token
      req_hash = generate_request('ListSubscriptionsByTopic', params)
      request_info(req_hash, SnsListSubscriptionsByTopicParser.new(:logger => @logger))
    rescue
      on_exception
    end
    
      # Subscribe a new endpoint to a topic
    def subscribe_to_topic(topic_arn, protocol, end_point)
      # TODO handle different SubscriptionArn results?  Let's
      # just return the raw subscription arn for now
      req_hash = generate_request('Subscribe', 'TopicArn' => topic_arn, 'Protocol' => protocol, 'Endpoint' => end_point)
      request_info(req_hash, SnsSubscribeParser.new(:logger => @logger))
    end
    
    # Add permissions to a topic.
    #
    #  sns.add_permissions('arn:aws:sns:us-east-1:464646271962:test',
    #                     'testLabel', ['125074342641','125074342642'],
    #                     ['Publish','Subscribe']) #=> true
    #
    #  +permissions+ is a hash of: AccountId => ActionName
    #  (valid ActionNames: * | Publish | Subscribe | Unsubscribe | GetTopicAttributes | SetTopicAttributes | ConfirmSubscription )
    def add_permissions(topic_arn, label, grantees, actions)
      params = {}
      # add each member
      grantees.each_with_index { |awsid,i| params.merge!("AWSAccountId.member.#{i + 1}" => awsid) }
      # add each action
      actions.each_with_index  { |action,i| params.merge!("ActionName.member.#{i + 1}" => action) }
      # standard params
      params.merge!('Label'    => label,
                    'TopicArn' => topic_arn )
      req_hash = generate_request('AddPermission', params)
      request_info(req_hash, SnsStatusParser.new(:logger => @logger))
    rescue
      on_exception
    end
    
    # Confirm a subscription given a topic arn and a token:
    #
    # sns.confirm_subscription('arn:aws:sns:us-east-1:464646271962:test', 'some_long_confirmation_token)
    #
    # Pass authenticate_on_unsubscribe as true to require the token for unsubscription.
    #
    # Note this has limited use cases, as currently when confirming the token is likely
    # held by a third party, so this call only makes sense if you have SNS subscribers
    # that have access to your SNS service as well.
    def confirm_subscription(topic_arn, token, authenticate_on_unsubscribe = false)
      req_hash = generate_request('ConfirmSubscription',
                                  'Token'    => token,
                                  'TopicArn' => topic_arn )
      request_info(req_hash, SnsSubscribeParser.new(:logger => @logger))                            
      
    end

    # Revoke any permissions in the topic policy that matches the +label+ parameter.
    #
    #  sns.remove_permissions('arn:aws:sns:us-east-1:464646271962:test',
    #                        'testLabel') # => true
    #
    def remove_permissions(topic_arn, label)
      req_hash = generate_request('RemovePermission',
                                  'Label'    => label,
                                  'TopicArn' => topic_arn )
      request_info(req_hash, SnsStatusParser.new(:logger => @logger))
    rescue
      on_exception
    end

      # Sets a topic attribute. Returns +true+ or an exception.
      #
      #  sns.set_topic_attributes('arn:aws:sns:us-east-1:464646271962:test', "DisplayName", "Wendy's Widgets") #=> true
      #
    def set_topic_attributes(topic_arn, attribute, value)
      req_hash = generate_request('SetTopicAttributes', 
                                  'AttributeName'  => attribute,
                                  'AttributeValue' => value,
                                  'TopicArn'       => topic_arn)
      request_info(req_hash, SnsStatusParser.new(:logger => @logger))
    rescue
      on_exception
    end

    #-----------------------------------------------------------------
    #      PARSERS: Status Response Parser
    #-----------------------------------------------------------------

    class SnsStatusParser < RightAWSParser # :nodoc:
      def tagend(name)
        if name == 'ResponseMetadata'
          @result = true
        end
      end
    end

    #-----------------------------------------------------------------
    #      PARSERS: SNS
    #-----------------------------------------------------------------

    class SnsCreateTopicParser < RightAWSParser # :nodoc:
      def tagend(name)
        @result = @text if name == 'TopicArn'
      end
    end

    class SnsListTopicsParser < RightAWSParser # :nodoc:
      def reset
        @result = []
      end
      def tagend(name)
        @result << @text if name == 'TopicArn'
      end
    end

    class SnsGetTopicAttributesParser < RightAWSParser # :nodoc:
      def reset
        @result = {}
      end
      def tagend(name)
        case name 
          when 'key'   then @current_attribute          = @text
          when 'value' then @result[@current_attribute] = @text
        end
      end
    end
    
    class SnsListSubscriptionsByTopicParser < RightAWSParser # :nodoc:
      def reset
        @result = { :members => [] }
      end
      def tagstart(name, attributes)
        case name
        when 'member' then @member = {}
      end
      def tagend(name)
        case name 
          when 'member' then @result[:members] << @member 
          when 'TopicArn' then @member['TopicArn'] = @text
          when 'Protocol' then @member['Protocol'] = @text
          when 'SubscriptionArn' then @member['SubscriptionArn'] = @text
          when 'Owner' then @member['Owner'] = @text
          when 'Endpoint' then @member['Endpoint'] = @text
          when 'NextToken' then @result[:next_token] = @text
          end
        end
      end
    end
    
    class SnsSubscribeParser < RightAWSParser # :nodoc:
      def tagend(name)
        @result = @text if name == 'SubscriptionArn'
      end
    end
  end
end
