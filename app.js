var express = require('express'),
bodyParser  = require('body-parser'),
mongoose    = require('mongoose'),
expressJWT  = require('express-jwt'),
jwt         = require('jsonwebtoken'),
bcrypt      = require('bcrypt'),
app         = express(),
logger      = require('morgan'),
Agent       = require('./models/agent');

var secret = "onhermajestyssecretservice";
mongoose.connect('mongodb://localhost:27017/MI6');

app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended:true}));

if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

app.use('/api/agents/:id', expressJWT({secret: secret}), function (error, request, response, next) {
  // send an appropriate status code & JSON object saying there was an error, if there was one.
  if (error.name === 'UnauthorizedError') {
    response.status(401).json({message: 'You need an authorization token to view confidential information.'});
  }
  next();
});

app.use('/api/safehouses', expressJWT({secret: secret}), function (error, request, response, next) {
  if (error.name === 'UnauthorizedError') {
    response.status(401).json({message: 'You need an authorization token to view confidential information.'});
  }
  next();
})

app.post('/api/authorizations', function(request, response){
  var agentParams = request.body;
  // some code to check that a user's credentials are right #bcryptmaybe?
  Agent.findOne({codename: agentParams.codename}, function (err, agent) {
    if (!agent) return response.status(404).json({message: "There is no agent by that codename"});
    // collect any information we want to include in the token, like that user's info
    agent.authenticate(agentParams.name, function (err, isMatch) {
      if (isMatch) {
        // make a token already & send it as JSON
        var token = jwt.sign(agent, secret);
        return response.json({agent: agent, token: token})
      } else {
        return response.status(401).json({message: "You dont have clearence, agent"});
      }
    });
  });
});

var routes = require('./config/routes');
app.use('/api', routes);

app.listen(3000);
