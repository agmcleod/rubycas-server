$(document).ready(function(){
  window.scrollTo(0,1);

  $('a.login_submit').closest('form').find('input').keydown(function(e) {
    if (e.which == 13) {
      $(this).closest('form').submit();
      return false;
    }
  });

  $('a.login_submit').click(function(){
    $(this).closest('form').submit();
    return false;
  });

  $('#login').focus();
});
