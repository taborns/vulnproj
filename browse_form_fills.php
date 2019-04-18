
<!doctype html>
<html>
    <head>
        <title>index</title>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <link type="text/css" rel="stylesheet" href="../public/css/bulma.css" />
        <link type='text/css' rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.css"/>
    </head>

  <body>
    <div id="app" class="container">

      <nav class="nav has-shadow">
        <div class="container">
          <div class="nav-left">
            <a href="/home" class="nav-item is-tab is-hidden-mobile is-active">PSD MGR</a>
          </div>
          <span class="nav-toggle">
            <span></span>
            <span></span>
            <span></span>
          </span>
          <div class="nav-right nav-menu">
            <a href="/home" class="nav-item is-tab is-hidden-tablet is-active">Home</a>
          </div>
        </div>
      </nav>

      <div class="container">
        <div class="columns" style="margin-top:10px">
          <div class="column is-one-quarter" style="margin-top:-60px">
            <p class="notification">
              <aside class="menu">
                  <p class="menu-label">
                    Repository
                  </p>
                  <ul class="menu-list">
                    <li>
                      <a class="">Display</a>
                      <ul>
                        <li><a href="vault">Vault</a></li>
                        <li><a href="notes">Notes</a></li>
                        <li><a href="form_fills" class='is-active'>Form Fills</a></li>
                      </ul>
                    </li>
                  </ul>
                      
                </aside>
            </p>

            <p class="notification">
              <p class="menu-label">New Form Fill</p>
            </p>

            <form method="Post" action="#">
              <div class="columns">

                <div class="column is-two-thirds">
                  <div class="field">
                    <p class="control">
                      <span class="select">
                        <select>
                          <option>Educational</option>
                          <option>Public</option>
                          <option>One Time</option>
                        </select>
                      </span>
                    </p>
                  </div>
                </div>
              </div>


              <div class="columns">

                <div class="column is-two-thirds">
                  <div class="field">
                    
                    <p class="control">
                      <input class="input" type="text" placeholder="First Name">
                    </p>
                  </div>
                </div>
              </div>

              <div class="columns">

                <div class="column is-two-thirds">
                  <div class="field">
                    
                    <p class="control">
                      <input class="input" type="text" placeholder="Last Name">
                    </p>
                  </div>
                </div>
              </div>

              <div class="columns">


                <div class="column is-two-thirds">
                  <div class="field">
                    
                    <p class="control">
                      <input class="input" type="text" placeholder="User Name">
                    </p>
                  </div>
                </div>
              </div>

              <div class="columns">

                <div class="column is-two-thirds">
                  <div class="field">
                    
                    <p class="control">
                      <input class="input" type="email" placeholder="Email">
                    </p>
                  </div>
                </div>
              </div>

              <div class="columns">

                <div class="column is-two-thirds">
                  <div class="field">
                    <p class="control">
                        <input type="radio" name="question">
                        Male
                      </label>
                      <label class="radio">
                        <input type="radio" name="question">
                        Female
                      </label>
                    </p>
                  </div>
                </div>
              </div>

              <div class="columns">
                <div class="column is-two-thirds">
                  <div class="field">
                    
                    <p class="control">
                      <input class="input" type="text" placeholder="Address ">
                    </p>
                  </div>
                </div>
              </div>

              <div class="columns">
                <div class="column is-two-thirds">
                  <div class="field">
                    <p class="control">
                      <input class="input button is-dark" type="submit" value="Add FormFill">
                    </p>
                  </div>
                </div>
              </div>
            </form>

          </div>

          <div class="column">


<?php
  $form_counts = $data['data']->count();
  $forms = $data['data'];
  $index = 0;
  while($index < $form_counts)
  {
    $form = $forms[$index];
?>
            <h4 class="title is-4"><?=$form->formtype?></h4>
            <div class="columns">

              <div class="column is-one-quarter">
                <div class="field">
                  
                  <p class="control">
                    <label class="label">Form Type</label>
                  </p>
                </div>
                
              </div>
              <div class="column is-two-thirds">
                <div class="field">
                  <p class="control">
                    <span class="select">
                      <select>
                        <option>Educational</option>
                        <option>Public</option>
                        <option>One Time</option>
                      </select>
                    </span>
                  </p>
                </div>
              </div>
            </div>


            <div class="columns">

              <div class="column is-one-quarter">
                <div class="field">
                  
                  <p class="control">
                    <label class="label">First Name</label>
                  </p>
                </div>
                
              </div>
              <div class="column is-two-thirds">
                <div class="field">
                  
                  <p class="control">
                    <input name="firstname" class="input" type="text" placeholder="First Name" value=<?=$form->firstname?>>
                  </p>
                </div>
              </div>
            </div>

            <div class="columns">

              <div class="column is-one-quarter">
                <div class="field">
                  
                  <p class="control">
                    <label class="label">Last Name</label>
                  </p>
                </div>
                
              </div>
              <div class="column is-two-thirds">
                <div class="field">
                  
                  <p class="control">
                    <input  name="lastname" class="input" type="text" placeholder="Last Name" value=<?=$form->lastname?>>
                  </p>
                </div>
              </div>
            </div>

            <div class="columns">

              <div class="column is-one-quarter">
                <div class="field">
                  
                  <p class="control">
                    <label class="label">User Name</label>
                  </p>
                </div>
                
              </div>
              <div class="column is-two-thirds">
                <div class="field">
                  
                  <p class="control">
                    <input class="input" name="username" type="text" placeholder="User Name" value=<?=$form->username?>>
                  </p>
                </div>
              </div>
            </div>

            <div class="columns">

              <div class="column is-one-quarter">
                <div class="field">
                  
                  <p class="control">
                    <label class="label">Email</label>
                  </p>
                </div>
                
              </div>
              <div class="column is-two-thirds">
                <div class="field">
                  
                  <p class="control">
                    <input name="email" class="input" type="email" placeholder="Email" value=<?=$form->email?>>
                  </p>
                </div>
              </div>
            </div>

            <div class="columns">

              <div class="column is-one-quarter">
                <div class="field">
                  
                  <p class="control">
                    <label class="label">Gender</label>
                  </p>
                </div>
                
              </div>
              <div class="column is-two-thirds">
                <div class="field">
                  <p class="control">
                      <input type="radio" name="gender"
                      <?php
                        if($form->gender == 1)
                        {
                          echo "checked='checked'";
                        }
                      ?>
                      >
                      Male
                    </label>
                    <label class="radio">
                      <input type="radio" name="gender"
                      <?php
                        if($form->gender == 0)
                        {
                          echo "checked='checked'";
                        }
                        ?>
                      >
                      Female
                    </label>
                  </p>
                </div>
              </div>
            </div>

            <div class="columns">

              <div class="column is-one-quarter">
                <div class="field">
                  
                  <p class="control">
                    <label class="label">Address</label>
                  </p>
                </div>
                
              </div>
              <div class="column is-two-thirds">
                <div class="field">
                  
                  <p class="control">
                    <input class="input" type="text" placeholder="Address ">
                  </p>
                </div>
              </div>
            </div>
<?php
    $index++;
  }

?>


            <!-- <h4 class="title is-4">Title 4</h4>
            <div class="columns">

              <div class="column is-one-quarter">
                <div class="field">
                  
                  <p class="control">
                    <label class="label">Form Type</label>
                  </p>
                </div>
                
              </div>
              <div class="column is-two-thirds">
                <div class="field">
                  <p class="control">
                    <span class="select">
                      <select>
                        <option>Educational</option>
                        <option>Public</option>
                        <option>One Time</option>
                      </select>
                    </span>
                  </p>
                </div>
              </div>
            </div>


            <div class="columns">

              <div class="column is-one-quarter">
                <div class="field">
                  
                  <p class="control">
                    <label class="label">First Name</label>
                  </p>
                </div>
                
              </div>
              <div class="column is-two-thirds">
                <div class="field">
                  
                  <p class="control">
                    <input class="input" type="text" placeholder="First Name">
                  </p>
                </div>
              </div>
            </div>

            <div class="columns">

              <div class="column is-one-quarter">
                <div class="field">
                  
                  <p class="control">
                    <label class="label">Last Name</label>
                  </p>
                </div>
                
              </div>
              <div class="column is-two-thirds">
                <div class="field">
                  
                  <p class="control">
                    <input class="input" type="text" placeholder="Last Name">
                  </p>
                </div>
              </div>
            </div>

            <div class="columns">

              <div class="column is-one-quarter">
                <div class="field">
                  
                  <p class="control">
                    <label class="label">User Name</label>
                  </p>
                </div>
                
              </div>
              <div class="column is-two-thirds">
                <div class="field">
                  
                  <p class="control">
                    <input class="input" type="text" placeholder="User Name">
                  </p>
                </div>
              </div>
            </div>

            <div class="columns">

              <div class="column is-one-quarter">
                <div class="field">
                  
                  <p class="control">
                    <label class="label">Email</label>
                  </p>
                </div>
                
              </div>
              <div class="column is-two-thirds">
                <div class="field">
                  
                  <p class="control">
                    <input class="input" type="email" placeholder="Email">
                  </p>
                </div>
              </div>
            </div>

            <div class="columns">

              <div class="column is-one-quarter">
                <div class="field">
                  
                  <p class="control">
                    <label class="label">Gender</label>
                  </p>
                </div>
                
              </div>
              <div class="column is-two-thirds">
                <div class="field">
                  <p class="control">
                      <input type="radio" name="question">
                      Male
                    </label>
                    <label class="radio">
                      <input type="radio" name="question">
                      Female
                    </label>
                  </p>
                </div>
              </div>
            </div>

            <div class="columns">

              <div class="column is-one-quarter">
                <div class="field">
                  
                  <p class="control">
                    <label class="label">Address</label>
                  </p>
                </div>
                
              </div>
              <div class="column is-two-thirds">
                <div class="field">
                  
                  <p class="control">
                    <input class="input" type="text" placeholder="Address ">
                  </p>
                </div>
              </div>
            </div>
                
          </div> -->



        </div>
      </div>
    </div>

    <script type="text/javascript">
      function collapse(id){
        divEl = document.getElementById(id);
        if(divEl.getAttribute('class') == "content is-hidden")
        {
          divEl.setAttribute('class','content');
          //alert(divEl.getAttribute('class'));
        } else {
          divEl.setAttribute('class','content is-hidden');
          //alert(divEl.getAttribute('class'));
          
      }
        }
    </script>

  </body>

</html>